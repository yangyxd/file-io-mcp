---
name: file-io-mcp
description: Enable when the file-io-mcp MCP tools are available, or for any task involving reading/writing/editing/searching files. Covers the encoding-safe edit loop, tool selection, and required key parameters.
---

# file-io-mcp usage notes

17 tools: text/binary read-write, precise editing, search, backup/rollback. Core goals: **encoding stays intact, changes are verifiable, reversible, and never overwrite each other under concurrency**. Full parameter lists are in each tool's `tools/list` schema (not repeated here).

## Selection (task -> tool)

- Read by line / prepare to edit -> `read_text_lines` (returns `sha256`)
- Read by byte / offset -> `read_text_file` (`strict=true` for exact bytes)
- Change many places at once (by original fragment, no line numbers known) -> `edit_file_sections` (all-or-nothing by default)
- By line number / anchor / context block -> `edit_file_lines` (context-block mode is mutually exclusive with `expected_old`, and **`expected_sha256` is required**)
- Read-only multi-file preview -> `preview_edits` (aggregates per-file diffs, one `planToken` per file)
- Pattern replace (supports `$1`; plain text uses `literal=true`) -> `regex_replace` (**`max_matches` is required**)
- Whole-file / binary write -> `write_text_file` / `write_binary_file` (HEX diff dry-run; `expected_hex` on binary)
- Search content (get line numbers + `sha256`, directly feed edits) -> `text_search` (`mode=regex|literal`)
- List directory / find files -> `list_files`; metadata / fingerprint -> `file_info`
- Backup / rollback -> `manage_backups`; delete file -> `delete_file` (**`confirm=true` required**)
- Copy / move -> `copy_files` / `move_files`

## Safe-edit loop (must follow)

1. `read_text_lines` reads the target -> get content and `sha256`.
2. Edit with **`dry_run=true` first** to see the diff.
3. Commit either by re-issuing the same call without `dry_run`, or with the returned `planToken` via `apply_plans(plan_tokens)` — one token = one file, so the content never has to be resent. Tokens are one-time (cleared on success or failure) and expire shortly.
4. After writing, handle by error code:
   - `E_EXTERNAL_CHANGED` -> re-read (get new `sha256`) and retry;
   - `E_GUARD_MISMATCH` / `E_NOT_FOUND` / `E_NOT_UNIQUE` -> re-read the target, fix `expected_old` / anchor / `anchor_occurrence`;
   - `E_INVALID_PARAM` -> fix the arguments per the message (e.g. `regex_replace` without `max_matches`) and retry;
   - `E_TOO_MANY_MATCHES` -> the match count exceeded `max_matches`; confirm the regex is not too broad, then raise the cap.
5. On a wrong change -> `manage_backups` with `action=undo`.

## Key rules

- **`expected_sha256` depends on the write type**: overwrite-style writes (`write_text_file` / `write_binary_file` with mode=overwrite) rewrite the whole file from the content you pass and MUST pass it, or they would overwrite others' edits. Local edits (`edit_file_lines` / `edit_file_sections` / `regex_replace` / `apply_plans`) locate within the **latest** content and therefore already preserve concurrent changes elsewhere — pass a sha only when you deliberately want strict snapshot checking, and **omit it by default: a stale one only turns a safe edit into a failure.** For line/fragment edits pass `expected_old` as well to prevent drift.
- **`dry_run` is never blocked by a stale sha256** (it writes nothing) and every preview returns a one-time `planToken`. Under concurrency, dry-run again to see the current state, then re-issue without `expected_sha256`; a multi-site rename is best done as one `preview_edits` batch then `apply_plans`.
- Keep the original encoding; don't force an `encoding` — specify it explicitly only when GBK/UTF-8 are hard to tell apart.
- `anchor_text` must match the whole line exactly (indentation included); use `anchor_occurrence` for multiple hits.
- **"Context block" small-range edit**: give `context_before` + `context_after` (two small context snippets) to locate the change point — the tool computes the implied old text and verifies it precisely, without repeating a large `expected_old`. Exclusive with `expected_old`/anchor/line-number, and **`expected_sha256` is required**. Both frames must be unique in the file, otherwise `E_NOT_UNIQUE`/`E_NOT_FOUND`.