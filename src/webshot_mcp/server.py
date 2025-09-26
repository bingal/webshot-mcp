import asyncio
import logging
from pathlib import Path
from typing import Any, Dict
import os
import time
import hashlib
import traceback
from urllib.parse import urlparse

from mcp.server import Server
from mcp.types import Tool, TextContent
from playwright.async_api import async_playwright
from PIL import Image

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建 MCP 服务器实例
server = Server("webshot-mcp")

# 缓存配置
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".webshot_cache")
CACHE_EXPIRE_TIME = 24 * 60 * 60  # 24小时缓存过期时间

# 确保缓存目录存在
os.makedirs(CACHE_PATH, exist_ok=True)

# 可缓存的文件扩展名
CACHEABLE_EXTENSIONS = {
    'js', 'css', 'png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 
    'woff', 'woff2', 'ttf', 'eot', 'ico', 'json'
}

# 需要精确匹配阻止的域名（只阻止这些特定域名）
BLOCKED_EXACT_DOMAINS = {
    # Google Analytics & Ads - 精确匹配
    'google-analytics.com', 'www.google-analytics.com', 'ssl.google-analytics.com',
    'googletagmanager.com', 'www.googletagmanager.com',
    'googleadservices.com', 'googlesyndication.com', 'googletagservices.com',
    'analytics.google.com', 'stats.g.doubleclick.net', 'googleads.g.doubleclick.net',
    'googletag.com', 'securepubads.g.doubleclick.net',
    
    # Microsoft Clarity - 精确匹配
    'clarity.ms', 'c.clarity.ms', 'www.clarity.ms',
    
    # Facebook Tracking - 精确匹配
    'connect.facebook.net',
    
    # 百度统计 - 精确匹配（避免阻止正常百度服务）
    'hm.baidu.com', 'hmcdn.baidu.com', 'tongji.baidu.com',
    
    # CNZZ统计 - 精确匹配
    'c.cnzz.com', 'w.cnzz.com', 's4.cnzz.com', 'cnzz.mmstat.com',
    
    # 51LA统计 - 精确匹配
    'js.users.51.la', 'v6-web.51.la',
    
    # 其他分析服务的特定子域名
    'static.hotjar.com', 'script.hotjar.com',
    'cdn.mxpnl.com', 'api.mixpanel.com',
    'cdn.segment.com', 'api.segment.io',
    'api.amplitude.com', 'cdn.amplitude.com',
    'fs.fullstory.com', 'edge.fullstory.com',
    'cdn.mouseflow.com', 'script.crazyegg.com',
    'pixel.quantserve.com', 'sb.scorecardresearch.com',
    'widgets.outbrain.com', 'cdn.taboola.com',
    'assets.growingio.com', 'api.growingio.com',
    'static.sensorsdata.cn', 'sdk.talkingdata.com', 'sdk.jpush.cn',
}

# 需要完全阻止的域名（阻止整个域名及其所有子域名）
BLOCKED_FULL_DOMAINS = {
    # 专门的广告/追踪域名（可以安全地完全阻止）
    'doubleclick.net', 'googlesyndication.com',
    'facebook.net', 'fbcdn.net',
    'hotjar.com', 'mixpanel.com', 'segment.com', 'amplitude.com',
    'fullstory.com', 'mouseflow.com', 'crazyegg.com',
    'quantserve.com', 'scorecardresearch.com',
    'outbrain.com', 'taboola.com',
    'amazon-adsystem.com',
    
    # 专门的统计域名
    'cnzz.com', '51.la', 'umeng.com',
    'growingio.com', 'sensorsdata.cn', 'talkingdata.com', 'jpush.cn',
}

# 需要阻止的URL路径模式
BLOCKED_PATTERNS = {
    '/gtag/', '/analytics/', '/ga.js', '/analytics.js', '/gtm.js',
    '/clarity.js', '/hotjar', '/mixpanel', '/segment', '/amplitude',
    '/facebook.net/', '/fbevents.js', '/fbpixel', '/connect.facebook.net/',
    '/hm.js', '/tongji', '/cnzz', '/umeng', '/growingio', '/sensorsdata',
    '/adsense/', '/doubleclick/', '/googlesyndication/', '/googleadservices/',
    '/outbrain/', '/taboola/', '/amazon-adsystem/', '/googletag/',
}

def md5(text: str) -> str:
    """生成MD5哈希值"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

async def _handle_resource_cache(route):
    """处理静态资源缓存的路由处理器"""
    try:
        request = route.request
        url = request.url
        method = request.method
        
        # 解析 URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # 检查域名是否需要阻止
        should_block_domain = False
        
        # 1. 精确匹配检查
        if domain in BLOCKED_EXACT_DOMAINS:
            should_block_domain = True
            logger.info(f"精确匹配阻止域名: {domain}")
        
        # 2. 完全阻止检查（包括子域名）
        if not should_block_domain:
            for blocked_domain in BLOCKED_FULL_DOMAINS:
                if domain == blocked_domain or domain.endswith('.' + blocked_domain):
                    should_block_domain = True
                    logger.info(f"完全阻止域名: {domain} (匹配规则: {blocked_domain})")
                    break
        
        # 检查是否为需要阻止的路径模式
        should_block_path = False
        for pattern in BLOCKED_PATTERNS:
            if pattern in path:
                should_block_path = True
                logger.info(f"路径模式阻止: {path}")
                break
        
        if should_block_domain or should_block_path:
            logger.info(f"阻止请求: {url}")
            await route.abort()
            return
        
        # 只缓存 GET 请求
        if method != 'GET':
            await route.continue_()
            return
        
        # 获取文件扩展名
        ext = os.path.splitext(parsed_url.path)[1][1:].lower()
        
        # 检查是否为可缓存的资源
        if ext not in CACHEABLE_EXTENSIONS:
            await route.continue_()
            return
        
        # 生成缓存文件名
        url_hash = md5(url)
        netloc_safe = parsed_url.netloc.replace(":", "-").replace("/", "_")
        cache_filename = f'{netloc_safe}_{url_hash}.{ext}'
        cache_filepath = os.path.join(CACHE_PATH, cache_filename)
        
        # 检查缓存是否存在且未过期
        if os.path.exists(cache_filepath):
            try:
                file_age = time.time() - os.path.getmtime(cache_filepath)
                if file_age < CACHE_EXPIRE_TIME:
                    # 使用缓存文件
                    await route.fulfill(path=cache_filepath)
                    return
                else:
                    # 缓存过期，删除文件
                    try:
                        os.remove(cache_filepath)
                    except:
                        pass
            except Exception as e:
                logger.warning(f"读取缓存失败 {url}: {e}")
        
        # 获取原始响应
        response = await route.fetch()
        body = await response.body()
        
        # 保存到缓存
        try:
            with open(cache_filepath, 'wb') as f:
                f.write(body)
        except Exception as e:
            logger.warning(f"保存缓存失败 {url}: {e}")
        
        # 返回响应
        await route.fulfill(
            response=response,
            body=body,
        )
        
    except Exception as e:
        logger.error(f"缓存处理异常 {route.request.url}: {e}")
        # 发生异常时继续正常请求
        await route.continue_()

async def _smart_scroll_page(page, target_height=0):
    """
    智能滚动页面以触发lazy load
    
    Args:
        page: Playwright页面对象
        target_height: 目标高度，0表示滚动到底部
    """
    try:
        logger.info(f"开始智能滚动，目标高度: {target_height}")
        
        # 获取页面初始信息
        page_info = await page.evaluate("""
            () => {
                return {
                    scrollHeight: document.documentElement.scrollHeight,
                    clientHeight: document.documentElement.clientHeight,
                    scrollTop: document.documentElement.scrollTop || document.body.scrollTop
                };
            }
        """)
        
        initial_height = page_info['scrollHeight']
        client_height = page_info['clientHeight']
        logger.info(f"页面初始高度: {initial_height}, 视口高度: {client_height}")
        
        # 确定滚动目标
        if target_height == 0:
            # 自适应模式：滚动到页面底部
            scroll_target = initial_height
            logger.info("自适应模式：滚动到页面底部")
        else:
            # 固定高度模式：滚动到指定位置
            scroll_target = min(target_height, initial_height)
            logger.info(f"固定高度模式：滚动到 {scroll_target}")
        
        # 分段滚动，每次滚动一个视口高度
        # 如果视口高度为0（自适应模式），使用默认滚动步长
        if client_height > 0:
            scroll_step = client_height * 0.8  # 每次滚动80%视口高度，确保有重叠
        else:
            scroll_step = 600  # 默认滚动步长
        current_scroll = 0
        scroll_count = 0
        max_scrolls = 20  # 最大滚动次数，防止无限循环
        
        while current_scroll < scroll_target and scroll_count < max_scrolls:
            scroll_count += 1
            next_scroll = min(current_scroll + scroll_step, scroll_target)
            
            logger.info(f"第{scroll_count}次滚动: {current_scroll} -> {next_scroll}")
            
            # 执行滚动
            await page.evaluate(f"window.scrollTo(0, {next_scroll})")
            
            # 等待滚动完成和可能的lazy load
            await asyncio.sleep(0.5)  # 给lazy load一些时间
            
            # 检查是否有新的网络请求
            try:
                await page.wait_for_load_state('networkidle', timeout=2000)
                logger.info("滚动后网络空闲")
            except:
                logger.info("滚动后网络仍有活动，继续")
                pass
            
            # 检查页面高度是否发生变化（lazy load可能增加内容）
            new_page_info = await page.evaluate("""
                () => {
                    return {
                        scrollHeight: document.documentElement.scrollHeight,
                        scrollTop: document.documentElement.scrollTop || document.body.scrollTop
                    };
                }
            """)
            
            new_height = new_page_info['scrollHeight']
            if new_height > initial_height:
                logger.info(f"检测到页面高度增加: {initial_height} -> {new_height}")
                initial_height = new_height
                # 如果是自适应模式，更新滚动目标
                if target_height == 0:
                    scroll_target = new_height
            
            current_scroll = next_scroll
        
        # 最终滚动到目标位置
        if target_height == 0:
            # 自适应模式：确保滚动到最底部
            await page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
            logger.info("最终滚动到页面底部")
        else:
            # 固定高度模式：滚动到指定位置的中间
            final_scroll = min(target_height / 2, scroll_target)
            await page.evaluate(f"window.scrollTo(0, {final_scroll})")
            logger.info(f"最终滚动到目标位置中间: {final_scroll}")
        
        # 最后等待一次，确保所有lazy load完成
        await asyncio.sleep(1)
        try:
            await page.wait_for_load_state('networkidle', timeout=3000)
            logger.info("智能滚动完成，网络空闲")
        except:
            logger.info("智能滚动完成，网络仍有活动")
            pass
            
        # 获取最终页面高度
        final_info = await page.evaluate("""
            () => {
                return {
                    scrollHeight: document.documentElement.scrollHeight,
                    scrollTop: document.documentElement.scrollTop || document.body.scrollTop
                };
            }
        """)
        
        logger.info(f"智能滚动完成，最终页面高度: {final_info['scrollHeight']}")
        
    except Exception as e:
        logger.error(f"智能滚动过程中出现错误: {str(e)}")
        logger.error(f"错误详情: {traceback.format_exc()}")

async def _add_stealth_script(context):
    """添加 stealth.js 脚本到浏览器上下文"""
    stealth_js_path = Path(__file__).parent / "stealth.js"
    if stealth_js_path.exists():
        await context.add_init_script(path=str(stealth_js_path))
        logger.info("已加载 stealth.js 反爬脚本")

async def _create_browser(p):
    """创建浏览器实例，优先使用系统浏览器"""
    
    # 浏览器启动参数
    browser_args = [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor'
    ]
    
    # 尝试使用系统 Chrome
    try:
        browser = await p.chromium.launch(
            channel="chrome",
            headless=True,
            args=browser_args
        )
        logger.info("✅ 使用系统 Chrome 浏览器")
        return browser, "Chrome"
    except Exception as e:
        logger.debug(f"无法使用系统 Chrome: {e}")
    
    # 尝试使用系统 Edge
    try:
        browser = await p.chromium.launch(
            channel="msedge",
            headless=True,
            args=browser_args
        )
        logger.info("✅ 使用系统 Microsoft Edge 浏览器")
        return browser, "Edge"
    except Exception as e:
        logger.debug(f"无法使用系统 Edge: {e}")
    
    # 兜底：使用默认 Chromium
    try:
        browser = await p.chromium.launch(
            headless=True,
            args=browser_args
        )
        logger.info("📦 使用 Playwright Chromium 浏览器")
        return browser, "Chromium"
    except Exception as e:
        logger.error(f"无法启动任何浏览器: {e}")
        raise

# 设备映射到 Playwright 内置设备
DEVICE_MAPPING = {
    "desktop": None,  # 使用自定义 viewport
    "mobile": "iPhone 13",  # 使用 Playwright 内置的 iPhone 13 配置
    "tablet": "iPad Pro 11"    # 使用 Playwright 内置的 iPad Pro 11 配置
}

@server.list_tools()
async def list_tools() -> list[Tool]:
    """列出可用的工具"""
    return [
        Tool(
            name="webshot",
            description="生成网页截图",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "要截图的网页 URL，比如: https://www.baidu.com"
                    },
                    "output": {
                        "type": "string", 
                        "description": "截图文件保存路径，比如: /path/to/screenshot.png"
                    },
                    "width": {
                        "type": "integer",
                        "description": "浏览器窗口宽度",
                        "default": 1280
                    },
                    "height": {
                        "type": "integer", 
                        "description": "浏览器窗口高度，0表示全页面截图",
                        "default": 768
                    },
                    "dpi_scale": {
                        "type": "number",
                        "description": "DPI 缩放比例",
                        "default": 2
                    },
                    "device": {
                        "type": "string",
                        "enum": ["desktop", "mobile", "tablet"],
                        "description": "截图设备类型",
                        "default": "desktop"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["png", "jpeg", "webp"],
                        "description": "截图文件格式",
                        "default": "png"
                    },
                    "quality": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "图片质量（仅对 jpeg 和 webp 有效）",
                        "default": 100
                    }
                },
                "required": ["url", "output"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> list[TextContent]:
    """处理工具调用"""
    if name != "webshot":
        raise ValueError(f"未知工具: {name}")
    
    try:
        result = await take_screenshot(**arguments)
        return [TextContent(type="text", text=result["message"])]
    except Exception as e:
        logger.error(f"截图失败: {e}")
        return [TextContent(type="text", text=f"截图失败: {str(e)}")]

async def take_screenshot(
    url: str,
    output: str,
    width: int = 1280,
    height: int = 768,
    dpi_scale: float = 2,
    device: str = "desktop",
    format: str = "png",
    quality: int = 100,
    max_retries: int = 3
) -> Dict[str, str]:
    """执行网页截图"""
    
    # 验证输入参数
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL 必须以 http:// 或 https:// 开头")
    
    if format not in ["png", "jpeg", "webp"]:
        raise ValueError("格式必须是 png、jpeg 或 webp")
    
    if quality < 0 or quality > 100:
        raise ValueError("质量必须在 0-100 之间")
    
    # 确保输出目录存在
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 重试机制
    last_error = None
    for attempt in range(max_retries):
        try:
            return await _take_screenshot_attempt(
                url, output_path, width, height, dpi_scale, device, format, quality
            )
        except Exception as e:
            last_error = e
            logger.warning(f"截图尝试 {attempt + 1}/{max_retries} 失败: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(1)  # 重试前等待1秒
            else:
                logger.error(f"所有截图尝试都失败了")
                raise last_error

async def _take_screenshot_attempt(
    url: str,
    output_path: Path,
    width: int,
    height: int,
    dpi_scale: float,
    device: str,
    format: str,
    quality: int
) -> Dict[str, str]:
    """单次截图尝试"""
    
    async with async_playwright() as p:
        # 启动浏览器，优先使用系统浏览器
        browser, browser_type = await _create_browser(p)
        
        try:
            # 创建页面或上下文，并获取实际使用的尺寸
            actual_width = width
            actual_height = height
            actual_dpi_scale = dpi_scale
            
            if device != "desktop" and device in DEVICE_MAPPING:
                device_name = DEVICE_MAPPING[device]
                if device_name in p.devices:
                    # 使用 Playwright 内置设备配置
                    device_config = p.devices[device_name]
                    context = await browser.new_context(**device_config)
                    await _add_stealth_script(context)
                    page = await context.new_page()
                    
                    # 获取设备的实际尺寸，避免后续强制调整导致变形
                    if 'viewport' in device_config:
                        actual_width = device_config['viewport']['width']
                        actual_height = device_config['viewport']['height'] if height != 0 else 0  # 保持全页面截图设置
                    if 'device_scale_factor' in device_config:
                        actual_dpi_scale = device_config['device_scale_factor']
                    
                    logger.info(f"使用设备 {device_name}，实际尺寸: {actual_width}x{actual_height if actual_height > 0 else '全页面'}, DPI: {actual_dpi_scale}")
                else:
                    # 回退到默认配置
                    context = await browser.new_context(
                        viewport={"width": width, "height": height},
                        device_scale_factor=dpi_scale
                    )
                    await _add_stealth_script(context)
                    page = await context.new_page()
            else:
                # 桌面设备使用自定义 viewport
                context = await browser.new_context(
                    viewport={"width": width, "height": height},
                    device_scale_factor=dpi_scale
                )
                await _add_stealth_script(context)
                page = await context.new_page()
            
            # 添加路由处理器来过滤不必要的请求和缓存静态资源
            await page.route("**/*", _handle_resource_cache)
            logger.info("已启用请求过滤和缓存机制")
            
            # 设置超时
            page.set_default_timeout(60000)  # 60秒超时
            page.set_default_navigation_timeout(60000)
            
            # 页面导航和加载
            logger.info(f"开始导航到页面: {url}")
            await page.goto(url, wait_until='domcontentloaded')
            logger.info("页面导航完成，等待基础加载")
            
            # 步骤1：等待基础加载
            try:
                await page.wait_for_load_state('load', timeout=20000)
                logger.info("页面基础加载完成")
            except Exception as e:
                logger.warning(f"基础加载超时，继续执行: {str(e)}")
            
            # 步骤2：等待网络空闲（较短超时）
            try:
                await page.wait_for_load_state('networkidle', timeout=8000)
                logger.info("网络空闲状态达成")
            except Exception as e:
                logger.warning(f"网络空闲超时，继续执行: {str(e)}")
            
            # 步骤3：智能滚动以触发lazy load
            logger.info("开始智能滚动以触发lazy load")
            await _smart_scroll_page(page, height)
            
            # 步骤4：处理自适应高度
            if height == 0:
                logger.info("自适应高度模式，重新获取页面高度")
                try:
                    # 滚动后重新获取页面高度
                    page_height = await page.evaluate('() => document.documentElement.scrollHeight')
                    logger.info(f"滚动后页面实际高度: {page_height}")
                    # 设置视口大小以适应页面高度，使用实际的设备宽度
                    await page.set_viewport_size({"width": actual_width, "height": page_height})
                    logger.info("视口大小调整完成")
                    
                    # 最后等待一次网络空闲
                    try:
                        await page.wait_for_load_state('networkidle', timeout=3000)
                        logger.info("最终网络空闲确认")
                    except:
                        logger.info("最终网络空闲超时，继续截图")
                        pass
                        
                except Exception as e:
                    logger.warning(f"自适应高度处理警告: {str(e)}")
            
            # 步骤5：最终等待网络空闲
            try:
                await page.wait_for_load_state('networkidle', timeout=5000)
                logger.info("最终网络空闲状态达成")
            except Exception as e:
                logger.warning(f"最终网络空闲超时，继续执行: {str(e)}")
            
            # 统一截图处理：Playwright 始终生成 PNG 格式
            # 然后通过 Pillow 处理格式转换、质量压缩和尺寸调整
            temp_png_path = output_path.with_suffix('.temp.png')
            screenshot_options = {
                "path": str(temp_png_path),
                "type": "png",
                "timeout": 30000  # 截图超时
            }
            
            # 全页面截图
            if height == 0:
                screenshot_options["full_page"] = True
            
            # 执行截图（始终生成 PNG）
            await page.screenshot(**screenshot_options)
            
            # 通过 Pillow 处理最终输出：格式转换、质量压缩、尺寸调整
            # 使用实际的设备尺寸，避免手机/平板截图变形
            await _process_final_image(
                temp_png_path, 
                output_path, 
                actual_width, 
                actual_height, 
                actual_dpi_scale, 
                format, 
                quality
            )
            
            # 删除临时 PNG 文件
            if temp_png_path.exists():
                temp_png_path.unlink()
            
            return {
                "status": "success",
                "message": f"截图已成功保存至 {output_path}"
            }
            
        except Exception as e:
            logger.error(f"截图过程中发生错误: {e}")
            raise
        finally:
            await browser.close()

async def _process_final_image(
    source_png_path: Path,
    output_path: Path,
    target_width: int,
    target_height: int,
    dpi_scale: float,
    format: str,
    quality: int
):
    """统一处理最终图片：格式转换、质量压缩、尺寸调整"""
    
    def process_sync():
        with Image.open(source_png_path) as img:
            # 1. 处理 DPI 缩放和尺寸调整
            # 由于 Playwright 使用了 dpi_scale，实际生成的图片尺寸是 target_width*dpi_scale x target_height*dpi_scale
            # 我们需要将其调整回用户请求的尺寸
            current_width, current_height = img.size
            
            # 如果是全页面截图（target_height == 0），保持原始宽度比例
            if target_height == 0:
                # 全页面截图：只调整宽度，高度按比例缩放
                if dpi_scale != 1:
                    new_width = target_width
                    new_height = int(current_height * (target_width / current_width))
                    img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            else:
                # 固定尺寸截图：调整到精确的目标尺寸
                if current_width != target_width or current_height != target_height:
                    img = img.resize((target_width, target_height), Image.Resampling.LANCZOS)
            
            # 2. 格式转换和质量压缩
            save_options = {"optimize": True}
            
            if format == "jpeg":
                # JPEG 格式：支持质量压缩
                if quality < 100:
                    save_options["quality"] = quality
                # 如果原图有透明通道，需要转换为 RGB
                if img.mode in ("RGBA", "LA", "P"):
                    # 创建白色背景
                    background = Image.new("RGB", img.size, (255, 255, 255))
                    if img.mode == "P":
                        img = img.convert("RGBA")
                    background.paste(img, mask=img.split()[-1] if img.mode == "RGBA" else None)
                    img = background
                img.save(output_path, format="JPEG", **save_options)
                
            elif format == "webp":
                # WebP 格式：支持质量压缩
                if quality < 100:
                    save_options["quality"] = quality
                    save_options["method"] = 6  # 最佳压缩方法
                img.save(output_path, format="WEBP", **save_options)
                
            elif format == "png":
                # PNG 格式：无损压缩，忽略 quality 参数
                img.save(output_path, format="PNG", **save_options)
                
            else:
                # 其他格式：尝试直接保存，忽略 quality 参数
                img.save(output_path, format=format.upper(), **save_options)
    
    # 在线程池中运行同步操作
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, process_sync)



def run_server():
    """运行服务器"""
    import mcp.server.stdio
    import asyncio
    
    async def main():
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    
    asyncio.run(main())

if __name__ == "__main__":
    run_server()
