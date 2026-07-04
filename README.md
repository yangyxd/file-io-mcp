# file-io-mcp

基于 Rust 实现的 MCP (Model Context Protocol) 文件 I/O 工具服务器，通过 stdio 传输协议为 AI 客户端提供文件操作和 HTTP 请求能力。

## 功能概览

共提供 **11 个工具**，覆盖文本/二进制文件读写、行编辑、搜索、正则处理、目录管理和网络请求。

| 工具 | 说明 |
|------|------|
| `read_text_file` | 读取文本文件，支持 offset/length 截取和多编码 |
| `write_text_file` | 写入文本文件，支持覆盖/追加/插入模式，自动创建目录 |
| `read_binary_file` | 读取二进制文件，返回 HEX dump 格式 |
| `write_binary_file` | 写入十六进制数据到二进制文件，支持覆盖/追加/插入/替换模式 |
| `edit_file_lines` | 按行编辑文件：删除行、插入行、替换行、追加行 |
| `text_search` | 搜索文件/目录中的文本内容（正则），支持后缀过滤和递归 |
| `regex_replace` | 正则替换文件文本，支持捕获组引用和全局/单次替换 |
| `list_files` | 列出/搜索目录内容，支持正则过滤、递归子目录、显示大小和修改时间 |
| `get_file_info` | 获取文件/目录元信息（大小、类型、修改时间） |
| `delete_file` | 删除指定文件（不可逆，需用户确认） |
| `fetch` | 发送 HTTP 请求，支持 GET/POST/PUT/DELETE/PATCH/HEAD |

## 技术栈

- **rmcp 0.16** — Rust MCP SDK，server + macros + transport-io
- **tokio** — 异步运行时
- **serde / serde_json** — 序列化
- **schemars** — JSON Schema 生成（工具参数描述）
- **regex** — 正则表达式
- **encoding_rs** — 高性能字符编码转换
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

### 作为 MCP 服务器运行

编译后直接通过 stdio 运行：

```bash
# 开发模式
cargo run

# 发布模式
./target/release/file-io-mcp
```

### 配置 MCP 客户端

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

## 工具详细说明

### read_text_file

读取文本文件内容。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始偏移量(字节)，默认 0 |
| `length` | usize | 否 | 读取长度(字节)，默认到末尾 |
| `encoding` | string | 否 | 字符编码，默认 utf-8 |
| `output_format` | string | 否 | 输出格式：`markdown`(默认，元信息+代码块) / `json`(纯文本格式) |

**支持的编码**：utf-8, gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr, utf-16le, utf-16be, iso-8859-1 等。

**输出格式说明：**

`markdown` 格式（默认）：
```
文件: data/config.txt
编码: utf-8
大小: 1024 字节
读取范围: 0 - 1024

```
文件内容放在代码块中，元信息和内容分离，
避免内容中的特殊字符造成混淆。
```

`json` 格式（与旧版兼容）：
```
文件: data/config.txt
编码: utf-8
大小: 1024 字节
读取范围: 0 - 1024
内容:
文件内容直接跟在后面
```

```json
// 使用 markdown 格式（默认）
{ "path": "data/config.txt", "encoding": "gbk" }

// 使用 json 格式（兼容旧版）
{ "path": "data/config.txt", "encoding": "gbk", "output_format": "json" }
```

### write_text_file

写入文本到文件。目录不存在时自动创建。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `content` | string | 是 | 写入内容 |
| `mode` | string | 否 | `overwrite`(默认) / `append` / `insert` |
| `offset` | u64 | 否 | insert 模式下的插入位置(字节) |
| `encoding` | string | 否 | 字符编码，默认 utf-8 |

```json
{ "path": "logs/app.log", "content": "新日志行\n", "mode": "append" }
```

### read_binary_file

读取二进制文件，返回 HEX dump 格式（含地址、十六进制和 ASCII 预览）。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始偏移量(字节) |
| `length` | usize | 否 | 读取长度(字节) |
| `output_format` | string | 否 | 输出格式：`markdown`(默认，元信息+代码块) / `json`(纯文本格式) |

```json
// markdown 格式（默认）
{ "path": "data/header.bin", "offset": 0, "length": 64 }

// json 格式（兼容旧版）
{ "path": "data/header.bin", "offset": 0, "length": 64, "output_format": "json" }
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
| `encoding` | string | 否 | 字符编码，默认 utf-8 |
| `output_format` | string | 否 | 输出格式：`text`(默认) / `json` |

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

搜索文件或目录中的文本内容（正则表达式）。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件或目录路径 |
| `pattern` | string | 是 | 正则表达式 |
| `case_sensitive` | bool | 否 | 区分大小写，默认 true |
| `max_results` | usize | 否 | 最大返回数，默认 100 |
| `extension` | string | 否 | 文件后缀过滤（如 `"java"`），仅目录时生效 |
| `recursive` | bool | 否 | 递归子目录，默认 true |
| `output_format` | string | 否 | 输出格式：`markdown`(默认，元信息+代码块) / `json`(纯文本格式) |

```json
// markdown 格式（默认）
{ "path": "src/", "pattern": "TODO.*fix", "extension": "java", "recursive": true }

// json 格式（兼容旧版）
{ "path": "src/", "pattern": "TODO.*fix", "extension": "java", "recursive": true, "output_format": "json" }
```

### regex_replace

使用正则表达式替换文件中的文本。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `pattern` | string | 是 | 正则表达式 |
| `replacement` | string | 是 | 替换内容，支持 `$1`, `$2` 捕获组引用 |
| `global` | bool | 否 | 全局替换，默认 true |

```json
{ "path": "config.yml", "pattern": "host:\\s*localhost", "replacement": "host: 192.168.1.100" }
```

### list_files

列出目录内容或按文件名正则搜索文件。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 目录路径 |
| `pattern` | string | 否 | 文件名正则过滤，不指定则列出所有 |
| `recursive` | bool | 否 | 递归子目录，默认 false |
| `include_dirs` | bool | 否 | 包含目录项，默认 true |
| `max_results` | usize | 否 | 最大返回数，默认 500 |
| `show_size` | bool | 否 | 显示文件大小，默认 true |
| `show_modified` | bool | 否 | 显示修改时间戳，默认 false |
| `output_format` | string | 否 | 输出格式：`markdown`(默认，表格) / `json`(纯文本格式) |

```json
// markdown 表格格式（默认）
{ "path": "src/", "pattern": ".*\\.rs$", "recursive": true }

// json 格式（兼容旧版）
{ "path": "src/", "pattern": ".*\\.rs$", "recursive": true, "output_format": "json" }
```

### get_file_info

获取文件或目录的元信息。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件/目录路径 |

返回：路径、类型（文件/目录）、大小(字节)、修改时间(UNIX 时间戳)。

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