import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import os

from mcp.server import Server
from mcp.types import Tool, TextContent
from playwright.async_api import async_playwright
from PIL import Image

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建 MCP 服务器实例
server = Server("webshot-mcp")

# 设备映射到 Playwright 内置设备
DEVICE_MAPPING = {
    "desktop": None,  # 使用自定义 viewport
    "mobile": "iPhone 13",  # 使用 Playwright 内置的 iPhone 13 配置
    "tablet": "iPad Pro"    # 使用 Playwright 内置的 iPad Pro 配置
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
        # 启动浏览器，添加更好的启动参数
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-web-security',
                '--disable-features=VizDisplayCompositor'
            ]
        )
        
        try:
            # 创建页面或上下文
            if device != "desktop" and device in DEVICE_MAPPING:
                device_name = DEVICE_MAPPING[device]
                if device_name in p.devices:
                    # 使用 Playwright 内置设备配置
                    context = await browser.new_context(**p.devices[device_name])
                    page = await context.new_page()
                else:
                    # 回退到默认配置
                    page = await browser.new_page(
                        viewport={"width": width, "height": height},
                        device_scale_factor=dpi_scale
                    )
            else:
                # 桌面设备使用自定义 viewport
                page = await browser.new_page(
                    viewport={"width": width, "height": height},
                    device_scale_factor=dpi_scale
                )
            
            # 设置超时
            page.set_default_timeout(30000)  # 30秒超时
            page.set_default_navigation_timeout(30000)
            
            # 导航到页面，使用更合适的等待策略
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                # 等待网络空闲，但设置较短的超时
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as e:
                logger.warning(f"页面加载警告: {e}，继续执行截图")
                # 如果网络空闲等待失败，至少确保 DOM 已加载
                await page.wait_for_load_state("domcontentloaded")
            
            # 截图选项
            screenshot_options = {
                "path": str(output_path),
                "type": format,
                "timeout": 30000  # 截图超时
            }
            
            # 全页面截图
            if height == 0:
                screenshot_options["full_page"] = True
            
            # 设置质量（仅对 jpeg 和 webp 有效）
            if format in ["jpeg", "webp"] and quality < 100:
                screenshot_options["quality"] = quality
            
            # 执行截图
            await page.screenshot(**screenshot_options)
            
            # 如果需要调整尺寸（当 dpi_scale 不为 1 且文件存在时）
            if dpi_scale != 1 and height != 0 and output_path.exists():
                await _resize_image(output_path, width, height, format, quality)
            
            return {
                "status": "success",
                "message": f"截图已成功保存至 {output_path}"
            }
            
        except Exception as e:
            logger.error(f"截图过程中发生错误: {e}")
            raise
        finally:
            await browser.close()

async def _resize_image(
    image_path: Path, 
    target_width: int, 
    target_height: int, 
    format: str, 
    quality: int
):
    """使用 Pillow 调整图片尺寸和质量"""
    
    # 在异步环境中运行同步的 Pillow 操作
    def resize_sync():
        with Image.open(image_path) as img:
            # 调整尺寸
            resized_img = img.resize((target_width, target_height), Image.Resampling.LANCZOS)
            
            # 保存选项
            save_options = {}
            if format == "jpeg":
                save_options["quality"] = quality
                save_options["optimize"] = True
            elif format == "webp":
                save_options["quality"] = quality
                save_options["method"] = 6  # 最佳压缩
            elif format == "png":
                save_options["optimize"] = True
            
            # 保存图片
            resized_img.save(image_path, format=format.upper(), **save_options)
    
    # 在线程池中运行同步操作
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, resize_sync)

def run_server():
    """运行服务器"""
    import mcp.server.stdio
    mcp.server.stdio.run_server(server)

if __name__ == "__main__":
    run_server()
