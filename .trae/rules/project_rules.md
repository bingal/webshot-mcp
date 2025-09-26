# webshot-mcp 一个用于生成网页截图的 mcp-server

## 项目依赖
- playwright: 调用浏览器打开网页并生成截图，使用异步代码习惯
- Pillow: 处理生成的截图，比如调整尺寸，压缩图片
- mcp[cli]: 用于开发 mcp-server 的框架，基于框架开发可以简化开发流程

## 项目文件

webshot-mcp/
│── pyproject.toml
│── README.md
│── webshot_mcp/
│   ├── __init__.py
│   ├── cli.py
│   └── server.py
└── tests/
    └── test_server.py
