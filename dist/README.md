# file-io-mcp

基于 Rust 实现的 MCP (Model Context Protocol) 文件 I/O 工具服务器，支持 **stdio**（默认）和 **Streamable HTTP** 两种传输模式，为 AI 客户端提供文件读写、编辑、搜索、备份回滚和 HTTP 请求能力。

设计目标：**编码不乱、改动可校验、写入可回滚、并发不互相覆盖**。

## 功能概览

共 **15 个工具**：

| 工具 | 说明 |
|------|------|
| `read_text_file` | 按字节读文本片段，返回编码与文件指纹 |
| `read_text_lines` | 按行读文本（带行号），编辑前取内容与指纹 |
| `write_text_file` | 整段写文本，支持覆盖/追加/插入，可 dry-run 预览 diff |
| `edit_file_lines` | 按行编辑：删/插/替/追，支持锚点定位与 `expected_old` 校验 |
| `edit_file_sections` | **批量精确替换**：一次调用改多处，默认全成或全不成，全部基于同一次快照定位 |
| `regex_replace` | 正则替换（`literal=true` 即免转义的纯文本替换），`max_matches` 必填防误伤，可 dry-run |
| `read_binary_file` | 读二进制 HEX dump |
| `write_binary_file` | 按十六进制写二进制（覆盖/追加/插入/替换），支持 `expected_hex` 写前校验与 HEX diff dry-run |
| `text_search` | 文件/目录内容搜索（`regex`/`literal` 双模式，结果按文件分组，带 sha256，可直接接 `edit_file_lines`） |
| `list_files` | 列目录 / 按文件名搜索（支持 glob） |
| `file_info` | 文件/目录元信息（大小、mtime、指纹、文本行数） |
| `manage_backups` | 备份管理：列出 / 回滚 / 清理 |
| `delete_file` | 删除文件（需 `confirm=true`，自动备份，可回滚） |
| `copy_files` | 复制文件 |
| `move_files` | 移动 / 重命名文件 |
| `fetch` | HTTP 请求 |

> **关于"必填"**：下文参数表中的"是"表示**运行时必填**（服务端会校验并返回明确错误码）。其中 `delete_file.confirm`、`regex_replace.max_matches`、`edit_file_lines.expected_old`、`edit_file_lines.path` 在 `tools/list` 的 schema 里是可省略字段（`Option`），省略即触发校验错误，属于有意设计（便于给出可读的错误提示）。

## 核心机制

### 1. 编码识别与保持

- **写入时默认保持原编码**，原文件有 BOM 则原样补回；显式指定的编码与实际不一致时**拒绝写入**并回报真实编码。
- **自动识别顺序**：BOM → 无 BOM 的 UTF-16 探测 → 纯 ASCII → UTF-8 合法性 → UTF-8/GBK 打分对比 → Big5/Shift_JIS/EUC-KR/EUC-JP 候选。
- **GBK 与 UTF-8 可靠区分**：大量 GBK 汉字的字节序列恰好也是合法 UTF-8（如 `隆` = `C2 A1`），仅凭"是否合法 UTF-8"会把 GBK 文件误判成 UTF-8 并写出乱码。因此工具会对两种候选分别解码并做"像不像中文文本"打分，取分数高者；两者接近时判定为**低置信度**并在返回头提示（建议显式指定 `encoding`）。
- **换行风格**：写入按文件的主换行风格（CRLF/LF 多数派）统一，避免出现混合换行。
- **非法字节保护**：解码时出现 `U+FFFD` 替换（内容已损坏）时**拒绝写回**，避免原字节被永久破坏。
- **支持的编码**：`utf-8`、`gbk`/`gb18030`、`big5`、`shift_jis`、`euc-jp`、`euc-kr`、`utf-16le`、`utf-16be`、`utf-32le`、`utf-32be`、`iso-8859-1`（含 `windows-125x`）等；UTF-16/UTF-32 由内置编解码实现（`encoding_rs` 不支持 UTF-32），读取、写入与搜索均已支持。
- **单次读取上限**：`read_text_file` 与 `read_text_lines` 最多 64MB（更大文件请用 `read_text_file` 的 offset/length 分页）、`read_binary_file` 单次最多 dump 4MB、`fetch` 响应体最多 8MB；被上限截断时返回头会标注 `⚠️已截断`。
- **路径回显**：路径回显为**相对服务进程当前目录**的写法（如 `src\main.rs`，不再出现 Windows 的 `\\?\` 前缀）；在当前目录之外时回显普通绝对路径（如 `F:\data\x.txt`）。相对入参也以当前目录为基准解析，故回显的路径可直接回传。备份与锁按绝对路径归一，同一文件的相对/绝对/大小写写法不会分裂成两份。想让回显更简短，就把启动时的当前目录设为实际要操作的项目目录。

### 2. 文件指纹（`sha256`）与并发写入

读取类工具在返回头给出 `sha256:<16位>`，它是**文件指纹**（≤1MB 用整份内容；>1MB 用"大小 + 头尾各 64KB"采样，避免为算指纹而重复读大文件）。同一算法贯穿读取、写入与 `file_info`，可直接互相使用。

多个 AI/进程同时改同一文件时：

- 写入工具传 `expected_sha256`（上次读到的值），写入前会重新校验；若文件已被他人改动，返回 **`E_EXTERNAL_CHANGED`** 而不是覆盖别人的修改 —— 此时应重新读取最新内容后再改。
- **同路径锁**：同一文件的"读-改-写"串行化。HTTP 模式用进程内锁；stdio 模式下每个 AI 是独立进程，额外使用**跨进程锁文件**（`<文件>.file-io-mcp.lock`，30 秒陈旧锁自动抢占、最长等待 10 秒后降级放行）。
- **原子写入**：先写同目录临时文件并 `sync_all`，再 `rename` 原子替换；读取方永远不会读到写了一半的文件。若 `rename` 因文件被 IDE/杀软占用而失败，回退为就地覆盖写（并先把备份转为独立副本），保证"原来能写的场景现在依然能写"。

### 3. 备份与回滚

- **位置**：MCP 工具**自身所在目录**下的 `.file-io-mcp-backups/<文件名>-<绝对路径hash16>/`，**不会污染被编辑的项目**。可用环境变量 `FILE_IO_BACKUP_DIR` 覆盖（例如 exe 目录不可写时）。
- **硬链接优先**：工具与被编辑文件同盘时用硬链接做零拷贝快照（因为原子写是"写临时文件 + rename 替换"，旧内容仍被硬链接引用）；跨盘自动退化为复制。
- **自动清理**：每个文件最多保留 **10 份**，超出自动删除最旧的（连同元数据）；单文件超过 **20MB** 不做备份；备份目录清空后自动删除。
- **不备份的情况**：`append` 模式（就地追加会让硬链接备份一起变化，语义上也难以回滚）。
- **回滚**：`manage_backups` 的 `undo` 会回滚最近一次写入或删除；若文件在备份之后又被改动过，默认拒绝（`force=true` 强制）。回滚前会先把当前内容存一份快照，所以"回滚"这个动作本身也能被撤销。

### 4. 错误码

所有错误消息以 `E_XXX` 开头，便于 AI 分流处理：

| 错误码 | 含义 | 建议动作 |
|--------|------|----------|
| `E_NOT_FOUND` | 目标不存在 / 锚点未匹配 / 无备份可回滚 | 确认路径，或先读取 |
| `E_NOT_UNIQUE` | 锚点命中多处 | 补全 `anchor_text` 或用 `anchor_occurrence` |
| `E_GUARD_MISMATCH` | `expected_old` / `expected_hex` 与实际不符 | 重新读取目标行（或目标字节）后再改 |
| `E_EXTERNAL_CHANGED` | 文件已被他人改动 | 重新读取（拿新 sha256）后重试 |
| `E_ENCODING` | 编码识别/解码/不一致 | 显式指定 `encoding` |
| `E_NO_PERMISSION` | 权限不足 | 检查文件占用/权限 |
| `E_READ` / `E_WRITE` | 读 / 写失败 | 查看具体原因 |
| `E_TOO_LARGE` | 文件过大（正则替换 >64MB） | 分段处理 |
| `E_TOO_MANY_MATCHES` | 匹配数超过 `max_matches` | 收窄正则或调整上限 |
| `E_INVALID_PARAM` | 参数错误 | 按提示修正参数 |

## 技术栈

- **rmcp 0.16** — Rust MCP SDK（server / macros / transport-io / transport-streamable-http-server）
- **axum 0.8** — HTTP 框架（HTTP 模式）
- **tokio** — 异步运行时
- **serde / serde_json** — 序列化
- **schemars** — JSON Schema 生成（工具参数描述）
- **regex** — 正则表达式
- **globset** — Glob 通配符匹配（支持 `**`、`*`、`?`）
- **encoding_rs** — 字符编码转换（UTF-16 由工具自身实现，保证编码/解码严格对称）
- **sha2** — 文件指纹
- **reqwest** — HTTP 客户端

## 编译

```bash
# 开发构建
cargo build

# 发布构建（推荐）
cargo build --release
```

**Windows MSVC 环境**：如编译时遇到 `LNK1104` 找不到 `msvcrt.lib`，需先引入 VS 环境或手动设置 `LIB`：

```powershell
$env:LIB = "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\lib\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
```

## 使用方式

### stdio 模式（默认）

```bash
cargo run                          # 开发
./target/release/file-io-mcp       # 发布
```

在 MCP 客户端（Claude Desktop、Cursor 等）配置：

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

#### 环境变量

| 变量 | 说明 |
|------|------|
| `FILE_IO_ROOT` | 可选。设置后所有文件操作被限制在该目录内（沙箱），未设置则不限制路径 |
| `FILE_IO_BACKUP_DIR` | 可选。备份根目录，默认 `<exe 所在目录>/.file-io-mcp-backups` |

沙箱判定说明：

- 越界路径一律拒绝（`E_NO_PERMISSION 路径超出允许的根目录`），包括 `..` 上跳、以及经符号链接 / junction 指向根目录之外的路径（会先解析真实路径再比对）；同前缀的兄弟目录（如根 `C:\data` 与 `C:\data-evil`）也会被正确拦截。
- 路径**写法差异不影响判定**：大小写不同（`c:\proj` vs `C:\Proj`）、8.3 短名（`PROJEC~1`）、`sub/..` 等都会被规范化后再比较；新建文件（目标尚不存在）会定位到最近的存在祖先，因此也能通过小写盘符 / 短名路径创建。
- 返回值（同时也是回显值）：在当前目录之下回显**相对路径**（如 `src\main.rs`），否则回显**去掉 `\\?\` 前缀的普通绝对路径**（如 `F:\data\x.txt`），详见上文「路径回显」；相对入参也以当前目录为基准解析。同一文件的不同写法会得到同一条字符串，备份/锁另按绝对路径归一，因此备份分区与指纹不会分裂。

### HTTP 模式（Streamable HTTP）

```bash
cargo run -- --http                                  # 默认 0.0.0.0:3000
cargo run -- --http --addr 127.0.0.1:8080            # 自定义地址
./target/release/file-io-mcp --http --addr 0.0.0.0:3000
```

客户端配置：

```json
{
  "mcpServers": {
    "file-io": { "url": "http://127.0.0.1:3000/mcp" }
  }
}
```

#### 命令行参数

| 参数 | 说明 |
|------|------|
| `--http` | 以 HTTP 模式启动（默认 stdio） |
| `--addr <ADDR>` | 监听地址，格式 `IP:PORT`，默认 `0.0.0.0:3000` |

#### 协议特性

- **有状态会话**：`mcp-session-id` 头部维持会话，支持 SSE 重连
- **SSE 流式响应**：`Accept: text/event-stream` 时以 SSE 返回
- **JSON 单次响应**：`Accept: application/json` 时返回普通 JSON
- **Keep-Alive**：每 15 秒 ping

## 工具详细说明

> 通用约定见上文"核心机制"：编码保持、`sha256` 指纹、`expected_sha256`、原子写入与备份，各工具不再重复说明。

### read_text_file

按字节读取文本片段，适合读配置、按偏移查看内容。要按行编辑请用 `read_text_lines`。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始字节偏移，默认 0 |
| `length` | usize | 否 | 读取字节数，默认上限 10MB（超出会截断并在返回头标注 ⚠️）；必须 ≥1。它默认只是**提示值**：为覆盖完整多字节字符可能多读几字节、`offset` 可能下取整到字符边界（返回头会标注实际区间） |
| `strict` | bool | 否 | true=按字节精确读取：不做“至少读 4 字节”、不对 `offset` 下取整；边缘切在字符中间时丢弃不完整字节并在返回头标注 |
| `encoding` | string | 否 | 编码，默认自动识别 |
| `show_line_numbers` | bool | 否 | 每行前显示行号，默认 false |

**返回头**：`路径 | 编码(BOM标注) | 大小 | sha256 | [起,止)`；编码识别不确定、区间被调整、边缘被丢弃时会追加 ⚠️ 提示；自动识别编码始终基于**完整文件**，不受分页窗口影响。需要“精确字节区间”时用 `strict=true`。

### read_text_lines

按行读取（1-based，带行号），与 `edit_file_lines` 配套。返回头包含总行数与 `sha256` —— 编辑同一文件时把它传给 `expected_sha256` 即可防止并发覆盖。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `start_line` | usize | 否 | 起始行号，默认 1 |
| `end_line` | usize | 否 | 结束行号（含），默认到末尾 |
| `encoding` | string | 否 | 编码，默认自动识别 |

**输出示例：**

```
src/main.rs | utf-8 | 4096B | 120 lines total | sha256:8f3a1c02d94b7e15 | [10-15]```
 10| fn foo() {
 11|     let x = 1;
 12| }
```

> 空文件按 `0 lines` 处理。

### write_text_file

整段写入文本，目录不存在时自动创建。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `content` | string | 是 | 写入内容 |
| `mode` | string | 否 | `overwrite`(默认) / `append` / `insert` |
| `offset` | u64 | 否 | insert 的插入字节偏移（必须落在字符边界，否则拒绝，防止把汉字劈开） |
| `encoding` | string | 否 | 默认保持原文件编码（新建文件默认 UTF-8；`utf-16le/be` 新建会自动带 BOM） |
| `expected_old` | string | 否 | 写前校验：overwrite=全文 / append=末尾 / insert=offset 附近，不符则拒绝；回显实际内容时超长内容只给头尾摘要+长度+指纹 |
| `expected_sha256` | string | 否 | 上次读到的指纹，文件被改动则拒绝写入 |
| `dry_run` | bool | 否 | true=只返回 diff 与预计指纹，不写文件 |

```json
{ "path": "logs/app.log", "content": "新日志行\n", "mode": "append" }
{ "path": "data/a.txt", "content": "新内容", "expected_old": "旧内容", "dry_run": true }
```

### edit_file_lines

按行编辑，行号 **1-based**。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `operation` | string | 是 | `delete_lines` / `insert_lines` / `replace_lines` / `append_lines` |
| `path` | string | 是（二选一） | 文件路径 |
| `file_path` | string | 否 | **已废弃**，仅为兼容旧调用保留，请改用 `path` |
| `start_line` | usize | 视操作 | 起始行号；与锚点参数二选一 |
| `end_line` | usize | 视操作 | 结束行号（含）；用锚点定位时可省（默认单行） |
| `content` | string | 视操作 | 插入/替换/追加的内容，多行用 `\n` 分隔 |
| `expected_old` | string | delete/replace 必填 | 目标行原文，用于二次校验 |
| `anchor_text` | string | 否 | **锚点定位**：目标行的完整文本，须全文唯一命中 |
| `anchor_regex` | string | 否 | 锚点定位：正则匹配目标行，须唯一命中 |
| `anchor_occurrence` | usize | 否 | 锚点命中多处时选第几处（1-based），默认要求唯一 |
| `expected_sha256` | string | 否 | 上次读到的指纹 |
| `encoding` | string | 否 | 默认保持原文件编码 |
| `dry_run` | bool | 否 | true=只返回 diff 预览 |

**操作说明：**

| 操作 | 必需参数 | 行为 |
|------|----------|------|
| `delete_lines` | `start_line`+`end_line`（或锚点） | 删除该范围 |
| `insert_lines` | `start_line`（或锚点 `anchor_occurrence`）+ `content` | 在该行**之前**插入 |
| `replace_lines` | `start_line`+`end_line`（或锚点）+ `content` | 用 `content` 替换该范围 |
| `append_lines` | `content` | 追加到文件末尾 |

**锚点定位**（免去行号计算，AI 更不容易改错位置）：

```json
{
  "operation": "replace_lines",
  "path": "src/unit1.pas",
  "anchor_text": "  FCount := 0;",
  "content": "  FCount := 1;",
  "expected_old": "  FCount := 0;"
}
```

- 未命中 → `E_NOT_FOUND`，并列出"包含该文本的行"作提示；
- 多处命中 → `E_NOT_UNIQUE` 并列出全部行号，可用 `anchor_occurrence` 指定第几处；
- `anchor_text` 必须与整行完全一致（含缩进）。

**示例**：删除第 3-5 行并校验

```json
{
  "operation": "delete_lines",
  "path": "data/file.txt",
  "start_line": 3,
  "end_line": 5,
  "expected_old": "old line 3\nold line 4\nold line 5"
}
```

### edit_file_sections

**一次调用改多处**的精确文本替换（补上 `edit_file_lines` 与 `regex_replace` 之间的空档：前者要算行号，后者要写正则）。
默认**全成或全不成**：任一片段未命中或不唯一就整体不写，不会只改一半。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `edits` | array | 是 | 片段列表，每项 `{expected_old, content, occurrence?}` |
| `edits[].expected_old` | string | 是 | 待替换的原始片段，须与文件内容**逐字符一致**（缩进/空行/标点都要对）；默认要求全文唯一命中 |
| `edits[].content` | string | 是 | 替换成的新内容；空串 = 删除该片段 |
| `edits[].occurrence` | usize | 否 | `expected_old` 命中多处时选第几处（1-based） |
| `edits[].start_line` | usize | 否 | 期望该片段**从原文第几行开始**(1-based)：可为多处相同的片段消歧（此时不再要求全文唯一）；声明的行号与实际位置不符时会直接告知实际行号 |
| `all_or_nothing` | bool | 否 | 默认 true；false = 只写命中的那些，其余在结果里列出 |
| `encoding` | string | 否 | 默认保持原文件编码（不一致则拒绝） |
| `expected_sha256` | string | 否 | 上次读到的指纹，防并发覆盖 |
| `dry_run` | bool | 否 | true = 只返回 diff 预览与预计指纹 |

- 所有片段都在**同一次快照**上定位，所以可以放心地“按原文”写多处改动；两条片段命中范围重叠会直接报错。
- `expected_old` 里的换行写 `\n` 或 `\r\n` 都可以（两侧归一后匹配），写回时按文件主换行风格还原；BOM/编码/备份/`expected_sha256` 与其他写工具一致。
- 成功时返回头**第二行**会回报每处改动的落点（**改动前**的行号，按文件顺序排列，下标对应你传入的 `edits`），例如：`改动位置(改动前行号): edits[1] 第 2 行、edits[0] 第 4~5 行`——不必再读一次文件就能核对“改的是不是我说的那几处”。

- **行号 + 文本双约束**：片段在文件里出现多次时，除了写更长的上下文，也可以给 `start_line`（如 `{ "expected_old": "dup = 1", "content": "DUP", "start_line": 3 }`）；行号写错时会直接告诉你它实际在第几行。
- `all_or_nothing=false` 时被跳过的条目会列在结果里；`dry_run=true` 时**同样会列出**，方便“先预览再决定”。

- 失败时：未命中给 `E_GUARD_MISMATCH`，命中多处给 `E_NOT_UNIQUE`（会列出各处行号），并明确告知“本次一处未改”。

```json
{ "path": "src/main.rs", "edits": [
  { "expected_old": "let a = 1;", "content": "let a = 2;" },
  { "expected_old": "// TODO: 清理", "content": "" } ] }
```


### regex_replace

正则替换，支持 `$1`/`$2` 捕获组。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `pattern` | string | 是 | 正则表达式；`literal=true` 时按纯文本处理 |
| `literal` | bool | 否 | true=纯文本替换：`pattern` 自动转义（`.*()` 等不再是元字符），`replacement` 里的 `$` 也按字面量填入。适合“把 A 精确换成 B”而懒得转义的场景 |
| `replacement` | string | 是 | 替换内容，支持 `$1`、`$2`（`literal=true` 时按字面量） |
| `max_matches` | usize | **是**（运行时） | 预期最多替换几处；实际匹配数超过该值即拒绝（防止正则过宽或匹配空串造成大范围误替换） |
| `global` | bool | 否 | 全局替换，默认 true；false 时只替换首个 |
| `dry_run` | bool | 否 | true=返回 diff 预览不写入 |
| `encoding` | string | 否 | 默认自动识别并保持原编码 |
| `expected_sha256` | string | 否 | 上次读到的指纹 |

> 文件超过 64MB 会被拒绝（防 OOM）。

```json
{ "path": "config.ini", "pattern": "host=\\S+", "replacement": "host=192.168.1.10", "max_matches": 1 }
{ "path": "data.txt", "pattern": "你好", "replacement": "Hello", "max_matches": 3, "dry_run": true }
```

### read_binary_file

读取二进制文件，返回 HEX dump（偏移 + 十六进制 + ASCII）。返回头含 `sha256`。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `offset` | u64 | 否 | 起始字节偏移，默认 0 |
| `length` | usize | 否 | 读取字节数，默认到末尾；单次最多 dump 4MB，超出会截断并在返回头标注 `⚠️已截断`（可用 offset 分页读剩余） |

### write_binary_file

按十六进制写二进制。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `hex_data` | string | 是 | 十六进制数据，如 `"48656C6C6F"` 或 `"0x48656C6C6F"`，也接受空格/冒号/逗号等分隔符（与 `expected_hex` 同一套宽松解析）。空串 = 0 字节：仅 `replace` 可用于删除字节，`overwrite` 需配 `confirm=true`，`append`/`insert` 直接拒绝 |
| `mode` | string | 否 | `overwrite`(默认) / `append` / `insert` / `replace` |
| `offset` | u64 | 否 | insert 为插入位置，replace 为替换起始位置 |
| `replace_length` | usize | 否 | replace 模式下被替换的字节数 |
| `expected_hex` | string | 否 | **写前校验待改范围的原始字节**（HEX，可带 `0x` 与空格/冒号分隔，便于从 HEX dump 直接粘贴；不能为空串——空串等于没校验，会被拒绝）。按 mode 取范围：`overwrite`=全文 / `append`=文件末尾 / `insert`=`offset` 起 / `replace`=`[offset, offset+replace_length)`；不符返回 `E_GUARD_MISMATCH` 并回显该范围的实际字节 |
| `expected_sha256` | string | 否 | 上次读到的指纹（整文件级，防外部改动） |
| `dry_run` | bool | 否 | true=只返回 HEX diff 预览与预计指纹，不写文件 |
| `confirm` | bool | 否 | `hex_data` 为空且 `mode=overwrite`（会清空文件）时必须传 `true` 才执行 |

```json
{ "path": "data/file.bin", "hex_data": "0xFF01", "mode": "replace", "offset": 3, "replace_length": 4 }
{ "path": "data/file.bin", "mode": "replace", "offset": 3, "replace_length": 4,
  "hex_data": "0xFF01", "expected_hex": "00 01 02 03", "dry_run": true }
```

- **越界不再静默截断**：`replace` 的 `offset + replace_length` 超出文件长度、或 `insert` 的 `offset` 超出文件长度时，直接返回错误（参数类），需先用 `read_binary_file` 确认真实长度与偏移。
- `dry_run` 输出形如：`[DRY-RUN] path | 4B→4B @4 | 16B→16B | sha256:…→…`，随后给出变更窗口的 `旧/新` HEX（窗口含前后 16 字节上下文，最长显示 256 字节）。

### text_search

在文件或目录中搜索文本（`mode=regex` 正则 / `mode=literal` 普通文本），结果**按文件分组**，每组给出 `sha256 / 编码 / 命中数`，命中行为 `行号:列 [命中片段] "整行原文"`。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件或目录（目录则搜索其下文件） |
| `pattern` | string | 是 | 搜索内容：`mode=regex` 时为正则，`mode=literal` 时为普通文本 |
| `mode` | string | 否 | `regex`(默认，正则) / `literal`(普通文本，pattern 里的 `. * [ ` 等一律当字面量) |
| `case_sensitive` | bool | 否 | 区分大小写，默认 true |
| `max_results` | usize | 否 | 最多返回条数，默认 100 |
| `extension` | string | 否 | 后缀过滤（如 `"pas"`），仅目录模式 |
| `extensions` | string[] | 否 | 多后缀过滤（如 `["pas","pp"]`），命中任一即可；与 `extension` 取并集 |
| `recursive` | bool | 否 | 递归子目录，默认 true（仅目录模式） |
| `encoding` | string | 否 | 默认 `auto`（逐文件自动识别，可区分 GBK/UTF-8）；显式指定则只按该编码解码，失败的文件会列入 `skipped` 而不是静默跳过 |
| `skip_hidden` | bool | 否 | 跳过隐藏文件/目录（以 `.` 开头，如 `.git`、`.env`），默认 true；`false` 则全都搜（仅目录模式） |
| `include` | string[] | 否 | glob 白名单，如 `["*.rs","src/**/*.ts"]`，任一命中才搜索（仅目录模式） |
| `exclude` | string[] | 否 | glob 黑名单，如 `["*.min.js","node_modules/**"]`；命中目录时整棵剪枝（仅目录模式） |
| `max_files` | usize | 否 | 目录模式最多收集多少文件，默认 `max_results*10` |
| `context_lines` | usize | 否 | 命中行前后各显示多少行，默认 0；>0 时相邻命中合并为一个上下文块 |

> 搜普通文本（含 `.`、`*`、`[` 等字符，或配置项、错误信息原文）时用 `mode: "literal"`，不用自己转义。
> 被隐藏规则挡掉的文件，可用 `include` 显式点名放行（如 `include: [".env"]`）。

glob 同时按**文件名**与**相对搜索根的路径**匹配：`"*.rs"` 匹配文件名，`"src/**/*.rs"` 匹配路径；目录剪枝额外按 `"{dir}/子项"` 试一次，所以 `"node_modules/**"` 也能剪掉 `node_modules` 目录本身。

> **大型项目建议显式排除构建产物目录**：`target/`、`node_modules/`、`dist/` 等不是隐藏目录，不会被 `skip_hidden` 挡掉，搜索时会产生大量噪音（例如 Rust 项目 `target/` 下就有成百上千个 `.rs`）。
>
> ```json
> { "path": "/proj", "pattern": "fn parse", "extensions": ["rs"],
>   "exclude": ["target/**", "node_modules/**", "dist/**", "build/**"] }
> ```

返回示例：

````
D:\proj\src | fn\s+foo | cs | 2/5 files | 3 matches | include:*.rs | pruned_dirs:1```
D:\proj\src\a.rs | sha256:1a2b3c4d5e6f7890 | enc:utf-8 | 2 matches
  12:5  [fn foo] "    fn foo(a: i32) -> i32 {"
  40:1  [fn foo] "fn foo() {}"
D:\proj\src\b.rs | sha256:9f8e7d6c5b4a3210 | enc:GBK | 1 matches
  7:3  [fn foo] "  fn foo() {"
⚠️ 候选文件已达上限 1000，目录可能未完全覆盖（已收集 1000 个，另有 12 个被过滤）。可提高 max_files 或收窄范围后重试
````

- 命中数写成 `返回数/实际数 matches(truncated)`（如 `100/137 matches(truncated)`）时表示已截断，末尾会附 `⚠️` 说明；未截断时就是 `N matches`。注意实际数只统计**已扫描范围**（达到 `max_results` 后不再继续扫描后续文件），所以它是下限而非全量真值。`pattern` 为空会被直接拒绝。
- 输出头的 `pruned_dirs` 统计被剪枝的目录数（`exclude` 命中 + 隐藏目录跳过）。
- 组头的 `sha256` 可直接作为 `edit_file_lines` / `write_text_file` 的 `expected_sha256`（支持前缀匹配），命中行保留原始缩进，可直接作为 `expected_old`。
- 列号按**字符数**计（不是字节偏移），中文行不会错位。
- 单行超过 300 字符会截断显示并标注总长度。

> 工具的备份目录与临时文件会自动从搜索结果中排除。

### list_files

列目录 / 按文件名搜索。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 目录路径 |
| `pattern` | string | 否 | 文件名正则过滤（与 `glob_pattern` 二选一） |
| `glob_pattern` | string | 否 | Glob 过滤，如 `"*.pas"`、`"**/*.rs"` |
| `recursive` | bool | 否 | 递归子目录，默认 false |
| `include_dirs` | bool | 否 | 包含目录项，默认 true |
| `max_results` | usize | 否 | 最多返回条数，默认 500 |
| `show_size` | bool | 否 | 显示大小，默认 true |
| `show_modified` | bool | 否 | 显示修改时间，默认 false |

### file_info

文件/目录元信息：`路径 | 类型 | 大小 | mtime(秒) | sha256`。

这里返回的 `sha256` 与读取工具同源，可直接作为写入时的 `expected_sha256`。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件或目录路径 |

### manage_backups

备份管理。备份位于工具自身目录（见"核心机制 3"），项目目录不会被污染。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 目标文件路径（备份按文件区分） |
| `action` | string | 是 | `list` / `undo` / `clean` |
| `keep` | usize | 否 | `clean` 保留份数，默认 10；`0` 表示清空 |
| `force` | bool | 否 | `undo` 时若文件在备份后又被改动，默认拒绝；true 强制回滚 |

```json
{ "path": "src/unit1.pas", "action": "list" }
{ "path": "src/unit1.pas", "action": "undo" }
{ "path": "src/unit1.pas", "action": "clean", "keep": 3 }
```

### delete_file

删除单个文件（不可删目录）。**必须显式传 `confirm=true`** 才会真正删除；删除前会自动备份，可用 `manage_backups` 的 `undo` 恢复。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 是 | 文件路径 |
| `confirm` | bool | 是（运行时） | 必须为 `true` 才执行删除；未传/false 时返回 `E_INVALID_PARAM` 并附文件大小与 sha256，不删任何东西 |

```json
{ "path": "src/old.pas", "confirm": true }
```

### copy_files

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sources` | string[] | 是 | 源文件路径列表 |
| `target` | string | 是 | 目标：多文件时为目录；单文件时视为新路径/文件名（目标不存在且不以 `/`、`\` 结尾），以分隔符结尾则视为目录 |
| `overwrite` | bool | 否 | 覆盖已存在的目标，默认 false（存在则跳过） |

```json
{ "sources": ["/a.txt", "/b.txt"], "target": "/dest/", "overwrite": true }
{ "sources": ["/a.txt"], "target": "/renamed.txt" }
```

### move_files

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sources` | string[] | 是 | 源文件路径列表 |
| `target` | string | 是 | 目标：多文件时为目录；单文件时视为新路径/文件名（目标不存在且不以 `/`、`\` 结尾），以分隔符结尾则视为目录 |
| `overwrite` | bool | 否 | 覆盖已存在的目标，默认 false（存在则跳过） |

```json
{ "sources": ["/a.txt", "/b.txt"], "target": "/dest/" }
{ "sources": ["/old.txt"], "target": "/new.txt" }
```

### fetch

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `url` | string | 是 | 请求 URL |
| `method` | string | 否 | GET(默认) / POST / PUT / DELETE / PATCH / HEAD |
| `headers` | object | 否 | 请求头 |
| `body` | string | 否 | 请求体（POST/PUT/PATCH） |
| `response_type` | string | 否 | `text`(默认) / `json`(格式化) / `binary`(HEX) |
| `timeout` | u64 | 否 | 超时秒数，默认 30 |

> 文本响应超过 100KB 会按**字符边界**截断并标注总大小。

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": { "Content-Type": "application/json" },
  "body": "{\"key\": \"value\"}",
  "response_type": "json"
}
```

## 典型工作流

**安全地改一个 Delphi 单元（GBK 编码、有并发）**

1. `read_text_lines` 读取目标行 → 拿到内容、总行号、`sha256`
2. `edit_file_lines` 用 `anchor_text` 定位 + `expected_old` 校验 + `expected_sha256` 防并发，先 `dry_run=true` 看 diff
3. 确认无误后去掉 `dry_run` 实写；若返回 `E_EXTERNAL_CHANGED`，重新读取后再改
4. 改错了用 `manage_backups` `action=undo` 回滚

## 项目结构

```
file-io-mcp/
├── Cargo.toml                  # 依赖配置
├── README.md                   # 本文件
├── build.bat                   # Windows 发布构建
├── start-http.bat              # HTTP 模式启动
└── src/
    └── main.rs                 # MCP 服务器实现（全部工具逻辑）
```

### 验证脚本（开发用）

| 脚本 | 覆盖内容 |
|------|----------|
| `mcp_test_p0.py` | 并发写、原子写、BOM 保持、换行统一、OCC |
| `mcp_test_encoding.py` | 编码保持、UTF-16、非法字节、`max_matches`、偏移边界 |
| `mcp_test_gbk_utf8.py` | GBK/UTF-8 区分（含"GBK 字节恰好合法 UTF-8"的冲突样本） |
| `mcp_test_backup.py` | 备份、回滚、清理、项目零污染 |
| `mcp_test_errcodes.py` | 各类失败的错误码 |
| `mcp_test_anchor_dryrun.py` | 锚点定位、dry-run/diff |
| `mcp_test_consistency.py` | 指纹口径一致性、空文件、`fetch` 截断 |
| `mcp_test_sandbox.py` | `FILE_IO_ROOT` 沙箱：大小写/8.3 短名/`..`/junction 的放行与拦截 |
| `mcp_test_binary.py` | 二进制 `expected_hex` 校验、`dry_run` HEX diff、越界报错、`matches(truncated)` 标注 |
| `mcp_bench.py` | 大文件性能基准（可选传 exe 路径） |
| `mcp_tools_size.py` | 统计 tools/list 的 schema 体量 |

运行方式：`python mcp_test_p0.py [可选 exe 路径]`（默认 `target/debug/file-io-mcp.exe`）
