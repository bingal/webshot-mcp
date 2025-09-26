

# webshot-mcp

[中文文档](README_zh.md) | English

A MCP (Model Context Protocol) server for generating web page screenshots, implemented with Playwright.

## Features

- 🌐 Support for any web page screenshots
- 📱 Support for multiple device types (desktop, mobile, tablet)
- 🎨 Support for multiple image formats (PNG, JPEG, WebP)
- 📏 Support for custom dimensions and DPI scaling
- 🖼️ Support for full-page screenshots
- 🗜️ Support for image quality compression
- ⚡ Asynchronous processing for excellent performance

## Usage

### As MCP Server

#### Method 1: Run directly with uvx (Recommended)

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

#### Method 2: Use with Claude Code

Claude Code can be configured to use this MCP server in two ways:

**Option A: Using the CLI wizard**
```bash
claude mcp add
```
Then follow the prompts to add webshot-mcp.

**Option B: Direct config file editing (Recommended)**

Edit your Claude Code configuration file (`~/.claude.json`) and add:

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

After editing the config file, restart Claude Code to apply the changes.

#### Method 3: Install with pip and run

```bash
# Install webshot-mcp
pip install webshot-mcp
# Install chromium browser
playwright install chromium
```

Then add to your MCP client configuration:

**For Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "webshot": {
      "command": "webshot-mcp"
    }
  }
}
```

**For Claude Code (`~/.claude.json`):**
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

### Tool Parameters

The `webshot` tool supports the following parameters:

#### Required Parameters

- `url` (string): URL of the web page to screenshot
- `output` (string): Path to save the screenshot file

#### Optional Parameters

- `width` (integer): Browser window width, default 1280
- `height` (integer): Browser window height, default 768. Set to 0 for full-page screenshot
- `dpi_scale` (number): DPI scaling ratio, default 2
- `device` (string): Device type, options:
  - `desktop` (default): Desktop device
  - `mobile`: Mobile device (iPhone 13)
  - `tablet`: Tablet device (iPad Pro)
- `format` (string): Image format, options:
  - `png` (default): PNG format
  - `jpeg`: JPEG format
  - `webp`: WebP format
- `quality` (integer): Image quality (0-100), default 100. Only effective for JPEG and WebP formats

### Usage Examples

#### Full-page Screenshot (Long Screenshot) Prompt Reference

```
Please generate a full-page screenshot of www.baidu.com, save it as WebP format to /Users/ben/Downloads/screenshot-baidu-1.webp
```

#### Custom Size Screenshot Prompt Reference

```
Please generate a screenshot of www.baidu.com with dimensions 1280x720, save it as WebP format to /Users/ben/Downloads/screenshot-baidu-2.webp
```

#### Mobile Device Screenshot Prompt Reference

*Note: Mobile and tablet devices will use their actual device dimensions, ignoring custom size parameters*

```
Please generate a mobile screenshot of www.baidu.com, save it as WebP format to /Users/ben/Downloads/screenshot-mobile.webp
```

#### Tablet Device Screenshot Prompt Reference

```
Please generate a tablet screenshot of www.baidu.com, save it as PNG format to /Users/ben/Downloads/screenshot-tablet.png
```

#### Custom Format and Quality Prompt Reference

```
Please generate a screenshot of www.baidu.com, save it as JPEG format with 80% quality to /Users/ben/Downloads/screenshot.jpg
```

#### High-resolution Desktop Screenshot Prompt Reference

```
Please generate a high-resolution screenshot of www.github.com with dimensions 1920x1080, save it as PNG format to /Users/ben/Downloads/github-hd.png
```

#### Batch Screenshots Prompt Reference

```
Please generate screenshots for the following websites and save them to /Users/ben/Downloads/:
1. www.google.com - full page, WebP format, filename: google-full.webp
2. www.github.com - 1280x720 size, JPEG format 90% quality, filename: github.jpg
3. www.stackoverflow.com - mobile view, PNG format, filename: stackoverflow-mobile.png
```

## Development

### Run Tests

```bash
uv run pytest
```

### Code Structure

```
webshot-mcp/
├── src/webshot_mcp/
│   ├── __init__.py
│   ├── cli.py          # CLI entry point
│   └── server.py       # MCP server implementation
├── tests/
│   └── test_server.py  # Test cases
├── pyproject.toml      # Project configuration
└── README.md
```

### Tech Stack

- **MCP**: Model Context Protocol framework
- **Playwright**: Browser automation and screenshots
- **Pillow**: Image processing and compression
- **asyncio**: Asynchronous programming support

## Publishing

### Build and Publish to PyPI

```bash
# Install build tools
uv add --dev build twine

# Build package
uv run python -m build

# Publish to PyPI
uv run twine upload dist/*
```

## License

MIT License

## Contributing

Issues and Pull Requests are welcome!

## Changelog

### v0.1.0

- Initial release
- Support for basic web page screenshot functionality
- Support for multiple device types and image formats
- Support for image quality compression and size adjustment