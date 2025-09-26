import asyncio
import tempfile
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from webshot_mcp.server import take_screenshot, list_tools, call_tool, server


class TestWebshotMCP:
    """webshot-mcp 服务器测试"""

    @pytest.mark.asyncio
    async def test_list_tools(self):
        """测试工具列表"""
        tools = await list_tools()
        assert len(tools) == 1
        assert tools[0].name == "webshot"
        assert "url" in tools[0].inputSchema["properties"]
        assert "output" in tools[0].inputSchema["properties"]

    @pytest.mark.asyncio
    async def test_call_tool_invalid_name(self):
        """测试调用无效工具名"""
        with pytest.raises(ValueError, match="未知工具"):
            await call_tool("invalid_tool", {})

    @pytest.mark.asyncio
    async def test_take_screenshot_invalid_url(self):
        """测试无效 URL"""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            with pytest.raises(ValueError, match="URL 必须以 http:// 或 https:// 开头"):
                await take_screenshot("invalid-url", tmp.name)

    @pytest.mark.asyncio
    async def test_take_screenshot_invalid_format(self):
        """测试无效格式"""
        with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as tmp:
            with pytest.raises(ValueError, match="格式必须是 png、jpeg 或 webp"):
                await take_screenshot("https://example.com", tmp.name, format="gif")

    @pytest.mark.asyncio
    async def test_take_screenshot_invalid_quality(self):
        """测试无效质量值"""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            with pytest.raises(ValueError, match="质量必须在 0-100 之间"):
                await take_screenshot("https://example.com", tmp.name, quality=150)

    @pytest.mark.asyncio
    @patch('webshot_mcp.server.async_playwright')
    async def test_take_screenshot_success(self, mock_playwright):
        """测试成功截图"""
        # 模拟 playwright
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        
        mock_context.__aenter__ = AsyncMock(return_value=mock_context)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        mock_context.chromium.launch = AsyncMock(return_value=mock_browser)
        
        mock_browser.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock()
        mock_browser.close = AsyncMock()
        
        mock_page.goto = AsyncMock()
        mock_page.screenshot = AsyncMock()
        mock_page.set_default_timeout = MagicMock()
        mock_page.set_default_navigation_timeout = MagicMock()
        mock_page.wait_for_load_state = AsyncMock()
        
        mock_playwright.return_value = mock_context

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            result = await take_screenshot("https://example.com", tmp.name, dpi_scale=1)
            
            assert result["status"] == "success"
            assert "截图已成功保存至" in result["message"]
            
            # 验证调用
            mock_page.goto.assert_called_once_with("https://example.com", wait_until="domcontentloaded", timeout=30000)
            mock_page.screenshot.assert_called_once()

    @pytest.mark.asyncio
    @patch('webshot_mcp.server.async_playwright')
    async def test_take_screenshot_full_page(self, mock_playwright):
        """测试全页面截图"""
        # 模拟 playwright
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        
        mock_context.__aenter__ = AsyncMock(return_value=mock_context)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        mock_context.chromium.launch = AsyncMock(return_value=mock_browser)
        
        mock_browser.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock()
        mock_browser.close = AsyncMock()
        
        mock_page.goto = AsyncMock()
        mock_page.screenshot = AsyncMock()
        mock_page.set_default_timeout = MagicMock()
        mock_page.set_default_navigation_timeout = MagicMock()
        mock_page.wait_for_load_state = AsyncMock()
        
        mock_playwright.return_value = mock_context

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            await take_screenshot("https://example.com", tmp.name, height=0)
            
            # 验证全页面截图参数
            call_args = mock_page.screenshot.call_args
            assert call_args[1]["full_page"] is True

    @pytest.mark.asyncio
    @patch('webshot_mcp.server.async_playwright')
    async def test_take_screenshot_mobile_device(self, mock_playwright):
        """测试移动设备截图"""
        # 模拟 playwright
        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        
        mock_context.__aenter__ = AsyncMock(return_value=mock_context)
        mock_context.__aexit__ = AsyncMock(return_value=None)
        mock_context.chromium.launch = AsyncMock(return_value=mock_browser)
        
        mock_browser.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock()
        mock_browser.close = AsyncMock()
        
        # 模拟 context 返回 page
        mock_context_obj = AsyncMock()
        mock_context_obj.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context.return_value = mock_context_obj
        
        mock_page.goto = AsyncMock()
        mock_page.screenshot = AsyncMock()
        mock_page.set_default_timeout = MagicMock()
        mock_page.set_default_navigation_timeout = MagicMock()
        mock_page.wait_for_load_state = AsyncMock()
        
        # 模拟 devices
        mock_playwright.return_value = mock_context
        mock_context.devices = {"iPhone 13": {"viewport": {"width": 390, "height": 664}}}

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            await take_screenshot("https://example.com", tmp.name, device="mobile", dpi_scale=1)
            
            # 验证使用了移动设备配置
            # 检查是否创建了 context（使用内置设备时）
            assert mock_browser.new_context.called or mock_browser.new_page.called

    def test_server_instance(self):
        """测试服务器实例"""
        assert server.name == "webshot-mcp"

    @pytest.mark.asyncio
    async def test_call_tool_success(self):
        """测试成功调用工具"""
        with patch('webshot_mcp.server.take_screenshot') as mock_screenshot:
            mock_screenshot.return_value = {"status": "success", "message": "截图成功"}
            
            result = await call_tool("webshot", {
                "url": "https://example.com",
                "output": "/tmp/test.png"
            })
            
            assert len(result) == 1
            assert result[0].text == "截图成功"

    @pytest.mark.asyncio
    async def test_call_tool_error(self):
        """测试工具调用错误"""
        with patch('webshot_mcp.server.take_screenshot') as mock_screenshot:
            mock_screenshot.side_effect = Exception("测试错误")
            
            result = await call_tool("webshot", {
                "url": "https://example.com", 
                "output": "/tmp/test.png"
            })
            
            assert len(result) == 1
            assert "截图失败" in result[0].text
            assert "测试错误" in result[0].text


if __name__ == "__main__":
    pytest.main([__file__])
