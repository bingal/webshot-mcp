# webshot-mcp

一个用于生成网页截图的 MCP (Model Context Protocol) 服务器，基于 Playwright 实现。

## 功能特性

- 🌐 支持任意网页截图
- 📱 支持多种设备类型（桌面、手机、平板）
- 🎨 支持多种图片格式（PNG、JPEG、WebP）
- 📏 支持自定义尺寸和 DPI 缩放
- 🖼️ 支持全页面截图
- 🗜️ 支持图片质量压缩
- ⚡ 异步处理，性能优异


## 使用方法

### 作为 MCP 服务器

#### 方式 1：使用 uvx 直接运行（推荐）

```json
{
  "mcpServers": {
    "webshot": {
      "command": "uvx",
      "args": ["webshot-mcp"]
    }
  }
}
```

#### 方式 2：在 Claude Code 中使用

Claude Code 可以通过两种方式配置此 MCP 服务器：

**选项 A：使用 CLI 向导**
```bash
claude mcp add
```
然后按照提示添加 webshot-mcp。

**选项 B：直接编辑配置文件（推荐）**

编辑你的 Claude Code 配置文件（`~/.claude.json`）并添加：

```json
{
  "mcpServers": {
    "webshot": {
      "type": "stdio",
      "command": "uvx",
      "args": ["webshot-mcp"]
    }
  }
}
```

编辑配置文件后，重启 Claude Code 以应用更改。

#### 方式 3：使用 pip 安装后运行

```bash
# 安装 webshot-mcp
pip install webshot-mcp
# 安装 chromium 浏览器
playwright install chromium
```

然后在 MCP 客户端配置中添加：

**对于 Claude Desktop（`claude_desktop_config.json`）：**
```json
{
  "mcpServers": {
    "webshot": {
      "command": "webshot-mcp"
    }
  }
}
```

**对于 Claude Code（`~/.claude.json`）：**
```json
{
  "mcpServers": {
    "webshot": {
      "type": "stdio",
      "command": "webshot-mcp"
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

#### 网页完整长度截图（网页长截图）提示词参考

```
帮我生成 www.baidu.com 页面完整截图，保存成 webp 格式，保存到 /Users/ben/Downloads/screenshot-baidu-1.webp
```

#### 指定网页截图尺寸提示词参考

```
帮我生成 www.baidu.com 页面截图，尺寸 1280x720，保存成 webp 格式，保存到 /Users/ben/Downloads/screenshot-baidu-2.webp
```

#### 移动设备截图提示词参考

*注意：手机和平板设备会根据模拟的设备尺寸生成，忽略自定义尺寸参数*

```
帮我生成 www.baidu.com 手机版截图，保存成 webp 格式，保存到 /Users/ben/Downloads/screenshot-mobile.webp
```

#### 平板设备截图提示词参考

```
帮我生成 www.baidu.com 平板版截图，保存成 png 格式，保存到 /Users/ben/Downloads/screenshot-tablet.png
```

#### 指定保存格式和压缩质量提示词参考

```
帮我生成 www.baidu.com 截图，保存成 jpg 格式，压缩质量为 80，保存到 /Users/ben/Downloads/screenshot.jpg
```

#### 高分辨率桌面截图提示词参考

```
帮我生成 www.github.com 高分辨率截图，尺寸 1920x1080，保存成 png 格式，保存到 /Users/ben/Downloads/github-hd.png
```

#### 批量截图提示词参考

```
帮我为以下网站生成截图并保存到 /Users/ben/Downloads/：
1. www.google.com - 完整页面，webp 格式，文件名：google-full.webp
2. www.github.com - 1280x720 尺寸，jpg 格式 90% 质量，文件名：github.jpg
3. www.stackoverflow.com - 手机版视图，png 格式，文件名：stackoverflow-mobile.png
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