# 开发一个调用 playwright 开启浏览器（headless 模式）打开指定的 url，等待页面加载完成之后生成截图的 mcp server

## 功能要求

### 支持的输入参数：

- url: 要打开的网页 url，必填
- output: 截图文件保存的路径，必填
- width: 可选，浏览器窗口宽度，用于设置 viewport，默认 1280
- height: 可选，浏览器窗口高度，用于设置 viewport，默认 768，如果高度为 0，则对整个网页进行截图，根据网页情况自动调整
- dpi_scale: 可选，高分屏，截图的 dpi 缩放比例，默认 2，根据需要可以设置为 1 等
- device: 可选，截图设备，可选值有 desktop、mobile、tablet，默认值为 desktop, 基于 playwright.devices
- format: 可选，截图文件格式，可选值有 png、jpeg、webp，默认值为 png
- quality: 可选，截图文件质量，可选值有 0-100，默认值为 100，仅当 format 为 jpeg 或 webp 时有效

### 支持的输出参数：

- status: 截图生成状态，可选值有 success、failed，默认值为 success
- message: 截图生成状态的详细信息，默认值为空字符串，如果成功则提示已经保存至 output 中

### 使用的技术方案

- playwright: 调用浏览器打开网页并生成截图，使用异步代码习惯
- Pillow: 处理生成的截图，比如调整尺寸，压缩图片，如果输入截图文件和输出的尺寸不同，比如 dpi_scale 不为 1，生成的截图是两倍尺寸，则输出的时候需要用pillow 重新调整尺寸。另外如果设置了 quality，需要用 pillow 压缩图片质量。
- mcp[cli]: 用于开发 mcp-server 的框架，基于框架开发可以简化开发流程

## 发布

最终把项目发布到 pypi