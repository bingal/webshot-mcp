

# webshot-mcp

一个用于生成网页截图的 MCP (Model Context Protocol) 服务器，基于 Playwright 和 Pillow 实现。

## 功能特性

- 🌐 支持任意网页截图
- 📱 支持多种设备类型（桌面、手机、平板）
- 🎨 支持多种图片格式（PNG、JPEG、WebP）
- 📏 支持自定义尺寸和 DPI 缩放
- 🖼️ 支持全页面截图
- 🗜️ 支持图片质量压缩
- ⚡ 异步处理，性能优异

## 安装

### 从源码安装

```bash
git clone <repository-url>
cd webshot-mcp
uv sync --extra dev
```

### 安装 Playwright 浏览器

```bash
uv run playwright install chromium
```

## 使用方法

### 作为 MCP 服务器

在你的 MCP 客户端配置中添加：

```json
{
  "mcpServers": {
    "webshot": {
      "command": "uv",
      "args": ["run", "python", "-m", "webshot_mcp.server"],
      "cwd": "/path/to/webshot-mcp"
    }
  }
}
```

### 工具参数

`webshot` 工具支持以下参数：

#### 必需参数

- `url` (string): 要截图的网页 URL
- `output` (string): 截图文件保存路径

#### 可选参数

- `width` (integer): 浏览器窗口宽度，默认 1280
- `height` (integer): 浏览器窗口高度，默认 768。设置为 0 时进行全页面截图
- `dpi_scale` (number): DPI 缩放比例，默认 2
- `device` (string): 设备类型，可选值：
  - `desktop` (默认): 桌面设备
  - `mobile`: 移动设备 (iPhone 13)
  - `tablet`: 平板设备 (iPad Pro)
- `format` (string): 图片格式，可选值：
  - `png` (默认): PNG 格式
  - `jpeg`: JPEG 格式
  - `webp`: WebP 格式
- `quality` (integer): 图片质量 (0-100)，默认 100。仅对 JPEG 和 WebP 格式有效

### 使用示例

#### 基本截图

```json
{
  "name": "webshot",
  "arguments": {
    "url": "https://example.com",
    "output": "/tmp/screenshot.png"
  }
}
```

#### 全页面截图

```json
{
  "name": "webshot", 
  "arguments": {
    "url": "https://example.com",
    "output": "/tmp/fullpage.png",
    "height": 0
  }
}
```

#### 移动设备截图

```json
{
  "name": "webshot",
  "arguments": {
    "url": "https://example.com",
    "output": "/tmp/mobile.png",
    "device": "mobile"
  }
}
```

#### 高质量 JPEG 截图

```json
{
  "name": "webshot",
  "arguments": {
    "url": "https://example.com", 
    "output": "/tmp/screenshot.jpg",
    "format": "jpeg",
    "quality": 90
  }
}
```

#### 自定义尺寸截图

```json
{
  "name": "webshot",
  "arguments": {
    "url": "https://example.com",
    "output": "/tmp/custom.png",
    "width": 1920,
    "height": 1080,
    "dpi_scale": 1
  }
}
```

## 开发

### 运行测试

```bash
uv run pytest
```

### 代码结构

```
webshot-mcp/
├── src/webshot_mcp/
│   ├── __init__.py
│   ├── cli.py          # CLI 入口
│   └── server.py       # MCP 服务器实现
├── tests/
│   └── test_server.py  # 测试用例
├── pyproject.toml      # 项目配置
└── README.md
```

### 技术栈

- **MCP**: Model Context Protocol 框架
- **Playwright**: 浏览器自动化和截图
- **Pillow**: 图片处理和压缩
- **asyncio**: 异步编程支持

## 发布

### 构建和发布到 PyPI

```bash
# 安装构建工具
uv add --dev build twine

# 构建包
uv run python -m build

# 发布到 PyPI
uv run twine upload dist/*
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v0.1.0

- 初始版本
- 支持基本网页截图功能
- 支持多种设备类型和图片格式
- 支持图片质量压缩和尺寸调整