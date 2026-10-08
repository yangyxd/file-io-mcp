---
name: file-io-mcp
description: 当 file-io-mcp 的 MCP 工具可用，或任何涉及用这些工具读/写/编辑/搜索文件、发 HTTP 时启用。编码安全编辑闭环、工具选型、关键必填参数。
---

# file-io-mcp 使用要点

15 个工具：文本/二进制读写、精确编辑、搜索、备份回滚、HTTP。核心目标：**编码不乱、改动可校验、可回滚、并发不互相覆盖**。各工具完整参数见其 `tools/list` schema（本 skill 不重复）。

## 选型（任务 → 工具）

- 按行读 / 准备编辑 → `read_text_lines`（返回带 `sha256`）
- 按字节 / 偏移读 → `read_text_file`（`strict=true` 取精确字节）
- 一次改多处（按原文片段，不知行号）→ `edit_file_sections`（默认全成或全不成）
- 按行号 / 锚点改 → `edit_file_lines`
- 模式替换（含 `$1`；纯文本用 `literal=true`）→ `regex_replace`（**`max_matches` 必填**）
- 二进制 → `read_binary_file` / `write_binary_file`（`expected_hex` 校验 + HEX diff dry-run）
- 搜内容（拿行号 + `sha256`，可直接喂编辑）→ `text_search`（`mode=regex|literal`）
- 列目录 / 找文件 → `list_files`；元信息 / 指纹 → `file_info`
- 备份 / 回滚 → `manage_backups`；删文件 → `delete_file`（**`confirm=true` 必填**）
- 复制 / 移动 → `copy_files` / `move_files`；HTTP → `fetch`

## 安全编辑闭环（必守）

1. `read_text_lines` 读目标 → 拿内容、`sha256`。
2. `edit_file_lines`（`anchor_text` 锚定 + `expected_old` 校验 + `expected_sha256`）+ **先 `dry_run=true`** 看 diff。
3. 实写后按错误码处理：
   - `E_EXTERNAL_CHANGED` → 重读（拿新 `sha256`）重试；
   - `E_GUARD_MISMATCH` / `E_NOT_FOUND` / `E_NOT_UNIQUE` → 重读目标，修正 `expected_old` / 锚点 / `anchor_occurrence`；
4. 改错 → `manage_backups` `action=undo`。

多处不相邻小改动优先 `edit_file_sections`（一次调用、同快照、省行号）。

## 关键守则

- **传 `expected_sha256`（上次读到的）防并发覆盖**；行 / 片段编辑传 `expected_old` 防漂移。
- 破坏性改动先 `dry_run=true`。
- **保持原编码，别强行指定 `encoding`**；仅 GBK/UTF-8 难分时显式指定。
- 锚点 `anchor_text` 须与整行完全一致（含缩进）；多处命中用 `anchor_occurrence`。
