# file-io-mcp

基于 Rust 实现的 MCP (Model Context Protocol) 文件 I/O 工具服务器，支持 **stdio**（默认）和 **Streamable HTTP** 两种传输模式，为 AI 客户端提供文件操作和 HTTP 请求能力。

## 功能概览

共提供 **13 个工具**，覆盖文本/二进制文件读写、行编辑、搜索、正则处理、文件批量操作、目录管理和网络请求。

| 工具 | 说明 |
|------|------|
| `read_text_file` | 读取文本文件，支持 offset/length 截取、多编码和自动编码检测 |
| `write_text_file` | 写入文本文件，支持覆盖/追加/插入模式，自动创建目录 |
| `read_binary_file` | 读取二进制文件，返回 HEX dump 格式 |
| `write_binary_file` | 写入十六进制数据到二进制文件，支持覆盖/追加/插入/替换模式 |
| `edit_file_lines` | 按行编辑文件：删除行、插入行、替换行、追加行 |
| `text_search` | 搜索文件/目录中的文本内容（正则），支持后缀过滤、递归和 BufReader 流式读取 |
| `regex_replace` | 正则替换文件文本，支持捕获组引用和全局/单次替换（64MB 文件上限） |
| `list_files` | 列出/搜索目录内容，支持正则过滤、glob 通配符、递归子目录、显示大小和修改时间 |
| `copy_files` | 批量复制文件到目标目录，或单文件复制为新文件名 |
| `move_files` | 批量移动文件到目标目录，或单文件重命名 |
| `file_info` | 获取文件/目录元信息（大小、类型、修改时间、SHA256） |
| `delete_file` | 删除指定文件（不可逆，需用户确认） |
| `fetch` | 发送 HTTP 请求，支持 GET/POST/PUT/DELETE/PATCH/HEAD |

## 技术栈

- **rmcp 0.16** — Rust MCP SDK，server + macros + transport-io + transport-streamable-http-server
- **axum 0.8** — HTTP 框架（HTTP 模式）
- **tokio** — 异步运行时
- **serde / serde_json** — 序列化
- **schemars** — JSON Schema 生成（工具参数描述）
- **regex** — 正则表达式
- **globset** — Glob 通配符匹配（支持 `**`、`*`、`?`）
- **encoding_rs** — 高性能字符编码转换与自动检测
- **reqwest** — HTTP 客户端

## 编译

```bash
# 开发构建
cargo build

# 发布构建（推荐）
cargo build --release
```

**Windows MSVC 环境**：如编译时遇到 `LNK1104: 无法打开文件 msvcrt.lib`，需设置 LIB 环境变量：
```powershell
$env:LIB = "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\lib\onecore\x64"
```
路径请根据实际 Visual Studio 安装位置调整。

## 使用方式

### stdio 模式（默认）

编译后直接通过 stdio 运行：

```bash
# 开发模式
cargo run

# 发布模式
./target/release/file-io-mcp
```

#### 配置 MCP 客户端

在 MCP 客户端（如 Claude Desktop、Cursor 等）的配置文件中添加：

```json
{
  "mcpServers": {
    "file-io": {
      "command": "F:\\mcp\\file-io-mcp.exe",
      "args": []
    }
  }
}
```

将 `command` 路径替换为实际的可执行文件路径即可。

### HTTP 模式（Streamable HTTP）

支持 [MCP Streamable HTTP 传输协议](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/transports/streamable-http/)，可通过 HTTP 端点提供 MCP 服务，适用于远程访问场景。

#### 启动服务

```bash
# 默认监听 0.0.0.0:3000
cargo run -- --http

# 自定义监听地址
cargo run -- --http --addr 127.0.0.1:8080

# 发布模式
./target/release/file-io-mcp --http --addr 0.0.0.0:3000
```

#### 配置 MCP 客户端

在支持 Streamable HTTP 的 MCP 客户端中配置 `url` 方式连接：

```json
{
  "mcpServers": {
    "file-io": {
      "url": "http://127.0.0.1:3000/mcp"
    }
  }
}
```

#### 命令行参数

| 参数 | 说明 |
|------|------|
| `--http` | 以 HTTP 模式启动（默认 stdio） |
| `--addr <ADDR>` | 监听地址，格式 `IP:PORT`，默认 `0.0.0.0:3000` |

#### 协议特性

- **有状态会话**：通过 `mcp-session-id` 头部维持会话，支持 SSE 重连
- **SSE 流式响应**：客户端发送 `Accept: text/event-stream` 时，服务端以 SSE 流式返回结果
- **JSON 单次响应**：客户端发送 `Accept: application/json` 时，返回普通 JSON 响应
- **Keep-Alive**：每 15 秒发送 ping 保持连接存活

## 工具详细说明

### read_text_file

读取文本文件内容。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始偏移量(字节)，默认 0 |
| `length` | usize | 否 | 读取长度(字节)，默认 256KB（未指定时自动限制，防止大文件 OOM） |
| `encoding` | string | 否 | 字符编码，默认 utf-8。设为 `"auto"` 自动检测（BOM → UTF-8 → GBK/Big5/Shift_JIS…） |

**支持的编码**：utf-8, gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr, utf-16le, utf-16be, iso-8859-1 等。

**输出格式：**
```
路径 | 编码 | 大小B | [起始,结束)```内容
```

```json
{ "path": "data/config.txt", "encoding": "auto" }
{ "path": "data/config.txt", "encoding": "gbk", "length": 1024 }
```

### write_text_file

写入文本到文件。目录不存在时自动创建。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `content` | string | 是 | 写入内容 |
| `mode` | string | 否 | `overwrite`(默认) / `append` / `insert` |
| `offset` | u64 | 否 | insert 模式下的插入位置(字节) |
| `encoding` | string | 否 | 字符编码，默认 utf-8。`"auto"` 时自动使用 UTF-8 |

```json
{ "path": "logs/app.log", "content": "新日志行\n", "mode": "append" }
{ "path": "data/file.txt", "content": "你好", "encoding": "auto" }
```

### read_binary_file

读取二进制文件，返回 HEX dump 格式（含地址、十六进制和 ASCII 预览）。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始偏移量(字节) |
| `length` | usize | 否 | 读取长度(字节) |

```json
{ "path": "data/header.bin", "offset": 0, "length": 64 }
```

### write_binary_file

将十六进制数据写入二进制文件。目录不存在时自动创建。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `hex_data` | string | 是 | 十六进制数据，支持 `"48656C6C6F"` 或 `"0x48656C6C6F"` 格式 |
| `mode` | string | 否 | `overwrite`(默认) / `append` / `insert` / `replace` |
| `offset` | u64 | 否 | insert 为插入位置，replace 为替换起始位置 |
| `replace_length` | usize | 否 | replace 模式下被替换的字节数 |

**replace 模式**：从 `offset` 起移除 `replace_length` 个字节，然后写入新数据（新旧长度可以不同）。

```json
{ "path": "data/file.bin", "hex_data": "0xFF01", "mode": "replace", "offset": 3, "replace_length": 4 }
```

### edit_file_lines

按行编辑文件内容，支持删除、插入、替换、追加四种行操作。行号从 **1 开始计数**。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `operation` | string | 是 | 操作类型：`delete_lines` / `insert_lines` / `replace_lines` / `append_lines` |
| `path` | string | 是（二选一） | 文件路径 |
| `file_path` | string | 是（二选一） | 文件路径（兼容别名） |
| `start_line` | usize | 视操作 | 起始行号（1-based），delete/insert/replace 使用 |
| `end_line` | usize | 视操作 | 结束行号（1-based），delete/replace 使用 |
| `content` | string | 视操作 | 要插入/替换/追加的内容，多行用 `\n` 分隔 |
| `encoding` | string | 否 | 字符编码，默认 utf-8。设为 `"auto"` 自动检测 |

**操作说明：**

| 操作 | 必需参数 | 行为 |
|------|----------|------|
| `delete_lines` | `start_line`, `end_line` | 删除 `start_line` 到 `end_line` 之间的所有行 |
| `insert_lines` | `start_line`, `content` | 在 `start_line` **之前**插入 `content` 内容 |
| `replace_lines` | `start_line`, `end_line`, `content` | 将 `start_line` 到 `end_line` 替换为 `content` |
| `append_lines` | `content` | 在文件末尾追加 `content` 内容 |

**示例：**

删除第 3-5 行：
```json
{ "operation": "delete_lines", "path": "data/file.txt", "start_line": 3, "end_line": 5 }
```

在第 10 行前插入两行：
```json
{ "operation": "insert_lines", "path": "data/file.txt", "start_line": 10, "content": "line1\nline2" }
```

替换第 2-4 行：
```json
{ "operation": "replace_lines", "path": "data/file.txt", "start_line": 2, "end_line": 4, "content": "new line" }
```

追加内容到末尾：
```json
{ "operation": "append_lines", "path": "data/file.txt", "content": "末尾新增行" }
```

### text_search

搜索文件或目录中的文本内容（正则表达式）。UTF-8 文件使用 BufReader 逐行流式读取，大文件不占用过多内存。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件或目录路径 |
| `pattern` | string | 是 | 正则表达式 |
| `case_sensitive` | bool | 否 | 区分大小写，默认 true |
| `max_results` | usize | 否 | 最大返回数，默认 100 |
| `extension` | string | 否 | 文件后缀过滤（如 `"java"`），仅目录时生效 |
| `recursive` | bool | 否 | 递归子目录，默认 true |
| `encoding` | string | 否 | 字符编码，默认 utf-8。`"auto"` 时每文件独立自动检测 |

```json
{ "path": "src/", "pattern": "TODO.*fix", "extension": "java", "recursive": true }
{ "path": "src/", "pattern": "fn", "encoding": "auto" }
```

### regex_replace

使用正则表达式替换文件中的文本。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `pattern` | string | 是 | 正则表达式 |
| `replacement` | string | 是 | 替换内容，支持 `$1`, `$2` 捕获组引用 |
| `global` | bool | 否 | 全局替换，默认 true |
| `encoding` | string | 否 | 字符编码，默认 utf-8。设为 `"auto"` 自动检测 |

> ⚠️ 文件大小限制：超过 64MB 的文件会返回错误提示，防止 OOM。

```json
{ "path": "config.yml", "pattern": "host:\\s*localhost", "replacement": "host: 192.168.1.100" }
{ "path": "data.txt", "pattern": "你好", "replacement": "Hello", "encoding": "auto" }
```

### list_files

列出目录内容或按文件名正则搜索文件。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 目录路径 |
| `pattern` | string | 否 | 文件名正则过滤，不指定则列出所有（与 `glob_pattern` 二选一） |
| `glob_pattern` | string | 否 | Glob 通配符过滤，如 `"**/*.rs"`、`"*.txt"`，比正则更直观（与 `pattern` 二选一） |
| `recursive` | bool | 否 | 递归子目录，默认 false |
| `include_dirs` | bool | 否 | 包含目录项，默认 true |
| `max_results` | usize | 否 | 最大返回数，默认 500 |
| `show_size` | bool | 否 | 显示文件大小，默认 true |
| `show_modified` | bool | 否 | 显示修改时间戳，默认 false |

```json
{ "path": "src/", "pattern": ".*\\.rs$", "recursive": true }
{ "path": "src/", "glob_pattern": "**/*.rs", "recursive": true }
{ "path": ".", "glob_pattern": "*.txt" }
```

### file_info

获取文件或目录的元信息，包括大小、类型、修改时间戳和 SHA256 哈希值。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件/目录路径 |

返回：路径、类型（文件/目录）、大小(字节)、修改时间(UNIX 时间戳)、SHA256 哈希值。

```json
{ "path": "data/report.csv" }
```

### delete_file

删除指定文件。**此操作不可逆，需要用户确认权限。**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |

- 文件不存在时返回提示（不报错）
- 路径为目录时拒绝删除

```json
{ "path": "temp/old_data.txt" }
```

### copy_files

批量复制文件到目标目录，或单文件复制为新文件名。支持自动创建父目录。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sources` | string[] | 是 | 源文件路径列表 |
| `target` | string | 是 | 目标路径。目录时多文件复制到该目录下；单文件时可指定新文件名 |
| `overwrite` | bool | 否 | 是否覆盖已存在的目标文件，默认 false |

- 多文件时目标必须是目录
- 单文件时目标可以是文件路径（重命名）

```json
{ "sources": ["/a.txt", "/b.txt"], "target": "/dest/", "overwrite": true }
{ "sources": ["/a.txt"], "target": "/b.txt" }
```

### move_files

批量移动文件到目标目录，或单文件重命名。支持自动创建父目录。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sources` | string[] | 是 | 源文件路径列表 |
| `target` | string | 是 | 目标路径。目录时多文件移动到该目录下；单文件时可指定新文件名 |
| `overwrite` | bool | 否 | 是否覆盖已存在的目标文件，默认 false |

- 多文件时目标必须是目录
- 单文件时目标可以是文件路径（重命名）
- 自动创建目标目录的父目录

```json
{ "sources": ["/a.txt", "/b.txt"], "target": "/dest/" }
{ "sources": ["/old_name.txt"], "target": "/new_name.txt" }
```

### fetch

发送 HTTP 请求，功能与浏览器 fetch API 一致。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `url` | string | 是 | 请求 URL |
| `method` | string | 否 | HTTP 方法，默认 GET。可选 GET/POST/PUT/DELETE/PATCH/HEAD |
| `headers` | object | 否 | 请求头键值对 |
| `body` | string | 否 | 请求体（POST/PUT/PATCH 时使用） |
| `response_type` | string | 否 | 响应格式：`text`(默认) / `json`(自动格式化) / `binary`(HEX) |
| `timeout` | u64 | 否 | 超时秒数，默认 30 |

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": { "Content-Type": "application/json", "Authorization": "Bearer token123" },
  "body": "{\"key\": \"value\"}",
  "response_type": "json"
}
```

## 项目结构

```
test/
├── Cargo.toml          # 项目依赖配置
├── README.md           # 本文件
└── src/
    └── main.rs         # MCP 服务器实现（全部工具逻辑）
```