---
alwaysApply: true
enabled: true
---

# 项目约定（AI 协作指南）

本项目是一个 Rust 编写的 MCP 服务 `file-io-mcp`（基于 `rmcp` 框架）。AI 在本仓库工作时，请遵守以下约定。

## 1. 文件读写：一律使用 file-io MCP 工具

本仓库自带 `file-io` MCP 服务器，AI 对**任何**文件（源码、文档、测试、配置）的读取、写入、编辑、搜索、备份都应优先调用 `file-io` 工具，**不要**使用 IDE 自带的通用文件读写工具。

## 2. 编译：一律使用 build.bat

本仓库是 Windows + `x86_64-pc-windows-msvc` 工具链，链接阶段需要 MSVC 运行时库与 Windows SDK 库文件。本机 Visual Studio 装在非默认盘（D 盘），`link.exe` 不会自动拾取这些库，因此**不要直接裸跑 `cargo build`**，而应通过 `build.bat` 编译。

`build.bat` 会自动完成：
1. 用 `vswhere.exe` 探测 VS 安装路径（兼容任意盘符）；
2. 取最新 MSVC 工具集与 Windows SDK 版本；
3. 自动设置 `LIB` 与 `link.exe` 的 `PATH`；
4. 执行 `cargo build --release`；
5. 编译成功后把 `file-io-mcp.exe` 复制到 `dist/`。

### 如何触发编译
- 方式一：直接双击 `build.bat`（脚本结尾带 `pause`，失败会停留提示）。
- 方式二：在命令行 / 终端执行 `build.bat`（推荐在需要看实时日志时用此方式，失败不会因 `pause` 卡住交互）。

### 说明 / 例外
- 仅需类型/语法检查（最快、不生成二进制）时，可临时用 `cargo check`；需要静态检查可用 `cargo clippy`。但这些都无法替代 `build.bat` 的完整 release 构建与产物复制。
- 编译失败提示 `cannot find msvcrt.lib` 等链接错误，根因是 `LIB` 未设置——这正是必须用 `build.bat` 的原因，不要手动裸 `cargo build`。
- 首次编译需联网拉取 crates 依赖。
