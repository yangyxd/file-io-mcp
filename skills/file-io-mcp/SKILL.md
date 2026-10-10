---
name: file-io-mcp
description: Enable when the file-io-mcp MCP tools are available, or for any task involving reading/writing/editing/searching files or making HTTP requests with these tools. Covers the encoding-safe edit loop, tool selection, and required key parameters.
---

# file-io-mcp usage notes

17 tools: text/binary read-write, precise editing, search, backup/rollback, HTTP. Core goals: **encoding stays intact, changes are verifiable, reversible, and never overwrite each other under concurrency**. Full parameter lists are in each tool's `tools/list` schema (not repeated here).

## Selection (task -> tool)

- Read by line / prepare to edit -> `read_text_lines` (returns `sha256`)
- Read by byte / offset -> `read_text_file` (`strict=true` for exact bytes)
- Change many places at once (by original fragment, no line numbers known) -> `edit_file_sections` (all-or-nothing by default)
- By line number / anchor / context block -> `edit_file_lines` (context-block mode is mutually exclusive with `expected_old`, and **`expected_sha256` is required**)
- Read-only multi-file preview -> `preview_edits` (aggregates per-file diffs, no write; returns a one-time `planToken` per file, committed via `apply_plans`)
- Pattern replace (supports `$1`; plain text uses `literal=true`) -> `regex_replace` (**`max_matches` is required**)
- Binary -> `read_binary_file` / `write_binary_file` (`expected_hex` check + HEX diff dry-run)
- Search content (get line numbers + `sha256`, directly feed edits) -> `text_search` (`mode=regex|literal`)
- List directory / find files -> `list_files`; metadata / fingerprint -> `file_info`
- Backup / rollback -> `manage_backups`; delete file -> `delete_file` (**`confirm=true` required**)
- Copy / move -> `copy_files` / `move_files`

## Safe-edit loop (must follow)

1. `read_text_lines` reads the target -> get content and `sha256`.
2. `edit_file_lines` (`anchor_text` anchor + `expected_old` check + `expected_sha256`) + **`dry_run=true` first** to see the diff.
3. After writing, handle by error code:
   - `E_EXTERNAL_CHANGED` -> re-read (get new `sha256`) and retry;
   - `E_GUARD_MISMATCH` / `E_NOT_FOUND` / `E_NOT_UNIQUE` -> re-read the target, fix `expected_old` / anchor / `anchor_occurrence`;
   - `E_INVALID_PARAM` -> fix the arguments per the message (e.g. `regex_replace` called without `max_matches`) and retry;
   - `E_TOO_MANY_MATCHES` -> the actual match count exceeded `max_matches`; confirm the regex is not too broad, then raise the cap to the expected value;
4. On a wrong change -> `manage_backups` with `action=undo`.

For several non-adjacent small changes, prefer `edit_file_sections` (one call, single snapshot, no line numbers).

## Key rules

- **Pass `expected_sha256` (from the last read) to prevent concurrent overwrites**; for line/fragment edits also pass `expected_old` to prevent drift.
- Do `dry_run=true` before destructive changes.
- **Keep the original encoding; don't force an `encoding`**; specify it explicitly only when GBK/UTF-8 are hard to tell apart.
- `anchor_text` must match the whole line exactly (indentation included); use `anchor_occurrence` for multiple hits.
- **"Context block" small-range edit**: give `context_before` + `context_after` (two small context snippets) to locate the change point (the tool computes the implied old text and verifies it precisely), without repeating a large `expected_old`; mutually exclusive with `expected_old`/anchor/line-number, and **`expected_sha256` is required** (file-level concurrency fallback). Both frames must be unique in the file, otherwise `E_NOT_UNIQUE`/`E_NOT_FOUND`.
- **Preview multi-file changes with `preview_edits` first**: pass several per-file edit descriptions in one call; it aggregates each file's small diff and summarizes success/failure counts -- fits workflows like "code change must sync a test page / doc".
- **Commit a preview with `planToken`**: each previewed file gets a one-time `planToken`; after confirming, call `apply_plans(plan_tokens)` (one token = one file) -- no need to resend the edit content. The target is re-located at commit, so non-overlapping concurrent edits auto-merge; pass `strict=true` to also require the file-level sha256 to match the preview snapshot. Tokens are cleared on success or failure and expire shortly, so on any error re-run `preview_edits`.
