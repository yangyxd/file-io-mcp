use rmcp::{
    handler::server::wrapper::Parameters,
    model::{
        PaginatedRequestParams, ReadResourceRequestParams, RawResource, Resource, ResourceContents,
        ListResourcesResult, ReadResourceResult, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_router, tool_handler,
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, transport::stdio,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, StreamableHttpServerConfig,
    session::local::LocalSessionManager,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use regex::Regex;
use globset::{Glob, GlobMatcher};
use sha2::{Sha256, Digest};
use include_dir::{include_dir, Dir};

const MAX_TEXT_READ_SIZE: usize = 10 * 1024 * 1024; // read_text_file default max read 10MB; beyond that the header clearly marks truncation
/// Hard cap on a single read for read_text_file / read_binary_file (even a huge length won't exceed this, to avoid memory/response blow-up)
const MAX_READ_HARD_LIMIT: usize = 64 * 1024 * 1024;
/// Max bytes dumped per call for read_binary_file (HEX dump is ~4-5x the raw byte size)
const MAX_BINARY_DUMP_LIMIT: usize = 4 * 1024 * 1024;
/// Max file size read_text_lines may load fully into memory (works line-by-line, cannot paginate)
const MAX_TEXT_LINES_FILE_SIZE: u64 = 64 * 1024 * 1024;

const MAX_REGEX_FILE_SIZE: u64 = 64 * 1024 * 1024; // regex_replace refuses files over 64MB

/// Retry count after a failed file op (5 retries beyond the first attempt)
const IO_RETRY_TIMES: usize = 5;
/// Wait time before each retry (ms)
const IO_RETRY_DELAY_MS: u64 = 120;

// ==================== Built-in Skill (compiled into the binary, exposed as an MCP Resource) ====================

/// Embeds the project's own `skills/file-io-mcp/SKILL.md` into the binary at compile time.
/// This skill is part of the file-io-mcp project, independent of any specific agent; per the MCP standard,
/// it is exposed as the resource `file-io-mcp://skill/guide` (see `list_resources`/`read_resource` below),
/// discovered by the client via `resources/list` and read via `resources/read`, with no non-standard install step.
const SKILL_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/skills/file-io-mcp");

// ==================== Unified error codes ====================

/// Error-code classification result: already-coded / inferred / unknown (caller supplies the default code)
enum ErrorCode {
    AlreadyCoded,
    Known(&'static str),
    Unknown,
}

/// All tools return errors as `E_XXX explanation` so the AI can route them directly.
/// Rules are matched in order, first hit wins; a message already carrying an E_ prefix is not rewritten.
/// The third column means "may also be hit in the param-validation path" -- a param-validation failure
/// cannot be a write/read failure, so runtime codes like E_WRITE/E_READ are excluded from param-error inference.
fn infer_error_code(msg: &str, param_side: bool) -> ErrorCode {
    if msg.starts_with("E_") {
        return ErrorCode::AlreadyCoded;
    }
    #[allow(clippy::type_complexity)]
    const RULES: &[(&[&str], &str, bool)] = &[
        (&["not unique", "multiple matches", "matches more than one"], "E_NOT_UNIQUE", true),
        (&["expected_old", "guard mismatch", "pre-write check failed"], "E_GUARD_MISMATCH", true),
        (
            &["encoding", "decode", "BOM", "UTF-8", "UTF-16", "U+FFFD"],
            "E_ENCODING",
            true,
        ),
        (&["not found", "does not exist", "cannot resolve path", "no such file"], "E_NOT_FOUND", true),
        (&["too many matches", "match count exceeds"], "E_TOO_MANY_MATCHES", true),
        // sandbox escape is a permission issue, classified separately (don't fold into E_TOO_LARGE)
        (&["outside allowed root", "sandbox"], "E_NO_PERMISSION", true),
        (&["too large", "exceeds size limit", "file too large"], "E_TOO_LARGE", true),
        (&["permission", "access denied", "not allowed"], "E_NO_PERMISSION", false),
        (&["HTTP", "request failed", "response"], "E_HTTP", false),
        (
            &["read", "open file", "seek", "metadata", "file info"],
            "E_READ",
            false,
        ),
        (
            &[
                "write", "append", "insert", "replace", "copy failed", "move failed",
                "create directory", "create parent", "delete failed", "mkdir",
            ],
            "E_WRITE",
            false,
        ),
    ];
    for (keys, code, allow_in_param) in RULES {
        if param_side && !allow_in_param {
            continue;
        }
        if keys.iter().any(|k| msg.contains(k)) {
            return ErrorCode::Known(code);
        }
    }
    ErrorCode::Unknown
}

/// Parameter errors (default E_INVALID_PARAM) -- same signature as McpError::invalid_params for easy swap-in
fn e_param<M: Into<String>>(message: M, data: Option<serde_json::Value>) -> McpError {
    let msg = message.into();
    let full = match infer_error_code(&msg, true) {
        ErrorCode::AlreadyCoded => msg,
        ErrorCode::Known(code) => format!("{} {}", code, msg),
        ErrorCode::Unknown => format!("E_INVALID_PARAM {}", msg),
    };
    McpError::invalid_params(full, data)
}

/// Runtime errors (default E_ERROR) -- same signature as McpError::internal_error
fn e_internal<M: Into<String>>(message: M, data: Option<serde_json::Value>) -> McpError {
    let msg = message.into();
    let full = match infer_error_code(&msg, false) {
        ErrorCode::AlreadyCoded => msg,
        ErrorCode::Known(code) => format!("{} {}", code, msg),
        ErrorCode::Unknown => format!("E_ERROR {}", msg),
    };
    McpError::internal_error(full, data)
}

// ==================== File-operation retries ====================

/// Decides whether an IO error is transient: commonly when a file is briefly locked by antivirus/indexer/editor/backup tools,
/// surfacing as "no permission to operate on the file" (PermissionDenied); retrying after a short wait usually succeeds.
fn is_retryable_io_error(e: &std::io::Error) -> bool {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::Interrupted => return true,
        _ => {}
    }
    // on Windows a locked file may surface only as a raw OS error code
    #[cfg(windows)]
    {
        if let Some(code) = e.raw_os_error() {
            // 5=ACCESS_DENIED, 32=SHARING_VIOLATION, 33=LOCK_VIOLATION, 1224=USER_MAPPED_FILE
            if matches!(code, 5 | 32 | 33 | 1224) {
                return true;
            }
        }
    }
    false
}

/// Runs a file operation with delayed retries on transient errors: up to IO_RETRY_TIMES retries,
/// each spaced IO_RETRY_DELAY_MS apart. Non-transient errors (e.g. path missing, disk full) return immediately.
fn retry_io<T, F: FnMut() -> std::io::Result<T>>(mut op: F) -> std::io::Result<T> {
    let mut last_err = match op() {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };
    for _ in 0..IO_RETRY_TIMES {
        if !is_retryable_io_error(&last_err) {
            return Err(last_err);
        }
        std::thread::sleep(std::time::Duration::from_millis(IO_RETRY_DELAY_MS));
        last_err = match op() {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
    }
    Err(last_err)
}

// ==================== Parameter structs ====================

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextFileParams {
    /// File path
    path: String,
    /// Start byte offset, default 0
    offset: Option<u64>,
    /// Bytes to read (>=1), default up to 10MB; when not strict this is a "hint" snapped to character boundaries (noted in the header)
    length: Option<usize>,
    /// true = read exactly [offset, offset+length), no >=4-byte look-ahead / offset floor; edge-incomplete bytes are dropped and noted
    strict: Option<bool>,
    /// Encoding, auto-detected by default
    encoding: Option<String>,
    /// Show a line number before each line, default false
    show_line_numbers: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextLinesParams {
    /// File path
    path: String,
    /// Start line number (1-based), default 1
    start_line: Option<usize>,
    /// End line number (1-based, inclusive), default to end
    end_line: Option<usize>,
    /// Encoding, auto-detected by default
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteTextFileParams {
    /// File path
    path: String,
    /// Content to write
    content: String,
    /// Mode: overwrite (default) / append / insert (needs offset)
    mode: Option<String>,
    /// Insert byte offset for insert (must land on a character boundary)
    offset: Option<u64>,
    /// Encoding, keep the original file encoding by default (rejected if inconsistent)
    encoding: Option<String>,
    /// Expected old content (per mode: overwrite=whole file / append=tail / insert=near offset); rejected with the actual content echoed on mismatch
    expected_old: Option<String>,
    /// sha256 read earlier; write rejected if the file changed since
    expected_sha256: Option<String>,
    /// true = return only a diff preview without writing
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadBinaryFileParams {
    /// File path
    path: String,
    /// Start byte offset, default 0
    offset: Option<u64>,
    /// Bytes to read, default to end; max 4MB per call (truncated and noted if exceeded)
    length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteBinaryFileParams {
    /// Hex data, e.g. "48656C6C6F" (0x/space/colon separators allowed); empty string = 0 bytes: only replace may delete bytes; overwrite needs confirm=true
    hex_data: String,
    /// Mode: overwrite (default) / append / insert / replace
    mode: Option<String>,
    /// insert = insert position / replace = start position (bytes)
    offset: Option<u64>,
    /// Bytes replaced for replace
    replace_length: Option<usize>,
    /// Pre-write check of the original bytes in the target range (HEX, 0x/space/colon allowed, must not be empty): overwrite=whole file / append=tail / insert=from offset / replace=[offset,+len); rejected with actual bytes echoed on mismatch
    expected_hex: Option<String>,
    /// sha256 read earlier; rejected if the file changed
    expected_sha256: Option<String>,
    /// true = return only the HEX diff preview and expected fingerprint, without writing
    dry_run: Option<bool>,
    /// Required true when hex_data is empty and mode is overwrite (would truncate the file)
    confirm: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ManageBackupsParams {
    /// File path
    path: String,
    /// list = enumerate backups / undo = roll back the most recent write or delete / clean = purge
    action: String,
    /// Copies to keep for clean, default 10; 0 = purge all
    keep: Option<usize>,
    /// When undoing, the file changed again after the backup: rejected by default, true forces rollback
    force: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileInfoParams {
    /// File or directory path
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RegexReplaceParams {
    /// File path
    path: String,
    /// Match pattern; parsed as regex by default, or as plain text when literal=true
    pattern: String,
    /// true = treat pattern as plain text (auto-escaped, metacharacters inert); $ in replacement is also taken literally
    literal: Option<bool>,
    /// Replacement text, supports $1/$2 capture groups (taken literally when literal=true)
    replacement: String,
    /// Encoding, auto-detected and kept by default
    encoding: Option<String>,
    /// Global replace, default true; false = replace only the first
    global: Option<bool>,
    /// true = return only a diff preview without writing
    dry_run: Option<bool>,
    /// Required: expected max number of replacements; rejected if actually exceeded (guards against over-broad regex)
    max_matches: Option<usize>,
    /// sha256 read earlier; write rejected if the file changed
    expected_sha256: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TextSearchParams {
    /// File or directory (a directory searches its files)
    path: String,
    /// Search content: plain text when mode=literal; regex when mode=regex
    pattern: String,
    /// Match mode: regex (default, regex) / literal (plain text; . * [ etc. in pattern are literal, no escaping needed)
    mode: Option<String>,
    /// Case-sensitive, default true
    case_sensitive: Option<bool>,
    /// Max results returned, default 100
    max_results: Option<usize>,
    /// Suffix filter (single), e.g. "pas"; equivalent to extensions with one item (directory mode only)
    extension: Option<String>,
    /// Suffix filter (multiple), e.g. ["pas","pp"], any match suffices (directory mode only)
    extensions: Option<Vec<String>>,
    /// Recurse into sub-directories, default true (directory mode only)
    recursive: Option<bool>,
    /// Encoding, default auto (per-file auto-detection, distinguishes GBK/UTF-8); explicit value decodes only with that encoding
    encoding: Option<String>,
    /// Skip hidden files and directories (starting with ., e.g. .git/.env), default true; false = search everything (directory mode only)
    skip_hidden: Option<bool>,
    /// Search only files matching these globs, e.g. ["*.rs","src/**/*.ts"]; any match suffices (directory mode only)
    include: Option<Vec<String>>,
    /// Skip files/dirs matching these globs, e.g. ["*.min.js","node_modules/**"]; a dir match prunes the whole subtree (directory mode only)
    exclude: Option<Vec<String>>,
    /// Directory mode: max candidate files to scan/collect (controls scan coverage, NOT the number of matches returned;
    /// hitting the cap emits a "may be incompletely covered" warning). Default 20000. Match count is controlled by max_results.
    max_files: Option<usize>,
    /// Context lines shown before and after each hit, default 0 (>0 merges adjacent hits in the same file)
    context_lines: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListFilesParams {
    /// Directory path
    path: String,
    /// Filename regex filter (choose one with glob_pattern)
    pattern: Option<String>,
    /// Glob filter, e.g. "*.pas", "**/*.rs" (choose one with pattern)
    glob_pattern: Option<String>,
    /// Recurse into sub-directories, default false
    recursive: Option<bool>,
    /// Include directory entries, default true
    include_dirs: Option<bool>,
    /// Max results returned, default 500
    max_results: Option<usize>,
    /// Show size, default true
    show_size: Option<bool>,
    /// Show modification time, default false
    show_modified: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeleteFileParams {
    /// File path
    path: String,
    /// Delete confirmation: must be explicitly true to actually delete; when false (unset) returns a hint and does not delete, preventing accidental deletion
    confirm: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileLinesParams {
    /// delete_lines/insert_lines/replace_lines/append_lines
    operation: String,
    /// File path
    path: Option<String>,
    /// [Deprecated, kept only for backward compatibility] same as path; prefer path
    file_path: Option<String>,
    /// Start line number (1-based): delete/insert/replace
    start_line: Option<usize>,
    /// End line number (1-based, inclusive): delete/replace; may be omitted when locating by anchor (single line by default)
    end_line: Option<usize>,
    /// Content for insert/replace/append
    content: Option<String>,
    /// Encoding, keep the original file encoding by default
    encoding: Option<String>,
    /// Required for delete/replace: original content of the target line(s), a second guard against miscounted line numbers
    expected_old: Option<String>,
    /// sha256 read earlier; write rejected if the file changed
    expected_sha256: Option<String>,
    /// Anchor location: full text of the target line (must match uniquely in the file); choose one with start_line
    anchor_text: Option<String>,
    /// Anchor location: regex matching the target line (must match uniquely)
    anchor_regex: Option<String>,
    /// When the anchor matches multiple places, which one to pick (1-based); unique match required by default
    anchor_occurrence: Option<usize>,
    /// true = return only a diff preview without writing
    dry_run: Option<bool>,
    /// Context-block mode (stronger): mutually exclusive with expected_old/anchor/line-number. With context_after, give small
    /// context snippets on both sides of the change point; the tool auto-locates the (implied) text between them and replaces it with content;
    /// two adjacent frames mean inserting content between them.
    /// Using this mode requires expected_sha256 (file-level concurrency guard fallback).
    context_before: Option<String>,
    /// Context block (see context_before): small context after the change point; both before/after must match uniquely and after must come after before
    context_after: Option<String>,
}

/// One edit description inside a multi-file preview (params match edit_file_lines, but path is inline and dry_run is forced to preview)
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PreviewEdit {
    /// File path
    path: String,
    /// delete_lines/insert_lines/replace_lines/append_lines; may be omitted in context-block mode (derived from context_before/after)
    operation: Option<String>,
    /// Insert/replace content (multi-line separated by \n)
    content: Option<String>,
    /// Original target line text (for delete/replace), mutually exclusive with context block
    expected_old: Option<String>,
    /// sha256 read earlier; if provided, the preview checks the file is unchanged (optional)
    expected_sha256: Option<String>,
    /// Anchor location: full target line text (must be unique in file)
    anchor_text: Option<String>,
    /// Anchor location: regex matching the target line (must be unique)
    anchor_regex: Option<String>,
    /// When the anchor matches multiple places, which one to pick (1-based)
    anchor_occurrence: Option<usize>,
    /// Start line number (1-based)
    start_line: Option<usize>,
    /// End line number (1-based, inclusive)
    end_line: Option<usize>,
    /// Context block (small context before the change point)
    context_before: Option<String>,
    /// Context block (small context after the change point)
    context_after: Option<String>,
    /// Encoding, keep the original file encoding by default
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PreviewEditsParams {
    /// List of per-file edit descriptions; each is an edit_file_lines-style change (read-only preview, no write, no backup)
    edits: Vec<PreviewEdit>,
    /// Global default encoding (overridable per edits[].encoding)
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CopyFilesParams {
    /// Source file path list
    sources: Vec<String>,
    /// Target: directory (multiple sources) or new file path (single source)
    target: String,
    /// Overwrite existing target, default false
    overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MoveFilesParams {
    /// Source file path list
    sources: Vec<String>,
    /// Target: directory (multiple sources) or new file path (single source, rename)
    target: String,
    /// Overwrite existing target, default false
    overwrite: Option<bool>,
}

/// One entry of a batch edit: locate expected_old exactly and replace with content
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SectionEdit {
    /// Original fragment to replace, must match char-by-char (may span multiple lines; \r\n may be written as \n)
    expected_old: String,
    /// New content; empty string = delete the fragment
    content: String,
    /// When multiple hits, which one to pick (1-based)
    occurrence: Option<usize>,
    /// Expected start line of the fragment (1-based); disambiguates, reports the actual line if wrong
    start_line: Option<usize>,
}

/// One successfully located section edit (internal): original range + new content + index in edits + pre-edit line range
struct PlannedSection {
    start: usize,
    end: usize,
    repl: String,
    idx: usize,
    line_from: usize,
    line_to: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileSectionsParams {
    /// File path
    path: String,
    /// Section list (located against a single snapshot)
    edits: Vec<SectionEdit>,
    /// Encoding, keep the original encoding by default (rejected if inconsistent)
    encoding: Option<String>,
    /// sha256 read earlier; write rejected if the file changed
    expected_sha256: Option<String>,
    /// true (default) = if any edit is unmatched/non-unique, write nothing; false = write only the matched ones and list the skipped
    all_or_nothing: Option<bool>,
    /// true = return only a diff preview without writing
    dry_run: Option<bool>,
}


// ==================== MCP server ====================

#[derive(Clone)]
struct FileIoServer {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    /// Root directory the server may access (sandbox). None means no path restriction.
    root: Option<std::path::PathBuf>,
}

/// Backup-related constants
const BACKUP_DIR_NAME: &str = ".file-io-mcp-backups";
/// Max backup copies kept per file (oldest auto-pruned beyond this)
const BACKUP_KEEP: usize = 10;
/// Files larger than this are not backed up (avoids large files repeatedly eating space)
const BACKUP_MAX_FILE_SIZE: u64 = 20 * 1024 * 1024;

/// A handle for one pre-write backup
struct BackupHandle {
    bak: std::path::PathBuf,
    meta: std::path::PathBuf,
}

/// Whether a file/dir is produced internally by this tool (backup dir / atomic-write temp file / cross-process lock file),
/// which listing and search should skip so they don't pollute the AI's view
fn is_internal_file(name: &str) -> bool {
    name == BACKUP_DIR_NAME
        || name.ends_with(".file-io-mcp.lock")
        || (name.contains(".file-io-mcp-") && name.ends_with(".tmp"))
}

/// Holder marker for the cross-process lock file: the lock file is deleted on Drop
struct FileLockGuard {
    /// Empty path means the lock was not acquired (degrades to no locking)
    path: std::path::PathBuf,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// File text: encoding + BOM + line-ending style + content.
/// Guarantees "what you read is what you write back" (BOM and line endings are not lost).
struct FileText {
    /// Canonical encoding name, e.g. "utf-8" / "GBK" / "UTF-16LE"
    encoding: String,
    /// BOM bytes the original file had; empty slice when there is no BOM
    bom: &'static [u8],
    /// Dominant line-ending style "\r\n" or "\n", used for newly added lines
    line_ending: &'static str,
    /// Body with BOM stripped
    content: String,
    /// Whether an undecodable byte appeared during lenient utf-8 decoding (to hint the AI)
    has_invalid: bool,
}

/// Logically normalizes a path: resolves `.` and `..`, and strips the Windows `\\?\` prefix,
/// for component-level prefix comparison (without touching the filesystem).
fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let s = p.to_string_lossy();
    // strip the Windows path prefixes \\?\ and \\.\
    let s = s.strip_prefix("\\\\?\\").or_else(|| s.strip_prefix("\\\\.\\")).unwrap_or(&s);
    let p = std::path::PathBuf::from(s);
    let mut parts: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(Component::Normal(_)) = parts.last() {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.into_iter().collect()
}

/// Directory-scan statistics: used to explain to the caller "what was searched, and why coverage may be incomplete"
#[derive(Default)]
struct SearchScanStat {
    /// Files filtered out by include/exclude/extension
    filtered: usize,
    /// Directories pruned entirely due to exclude
    pruned_dirs: usize,
    /// Whether scanning stopped early because the max_files cap was hit (directory may be incompletely covered)
    capped: bool,
    /// Files skipped by the "default binary/build-artifact suffix" rule when extension/extensions/include are not given
    default_filtered: usize,
}

/// Suffixes skipped by default when extension/extensions/include are not given (only these are skipped;
/// all other text/source suffixes are collected normally, so the max_files budget isn't wasted on binaries and real source isn't missed)
const DEFAULT_SKIP_EXTS: &[&str] = &[
    "dcu", "exe", "dll", "res", "obj", "o", "class", "pyc", "pyo", "so", "a", "lib", "pch", "idb",
    "ncb", "aps", "map", "ilk", "pdb", "tlog", "bak", "tmp", "cache", "lock", "dat", "bin",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx", "mp3", "mp4", "wav", "avi", "zip", "gz", "tar", "rar", "7z", "sqlite", "db",
    "ttf", "otf", "woff", "woff2", "eot",
];

impl FileIoServer {
    fn new(root: Option<std::path::PathBuf>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            root,
        }
    }

    /// Acquires the serialization lock for a path. The same path (same string) returns the same lock.
    /// Uses a process-level global lock table: under HTTP mode each session is a separate FileIoServer instance,
    /// and only a global table lets different sessions share the same lock (otherwise the "same-process multi-session mutual exclusion" promise wouldn't hold).
    fn lock_for(&self, path: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
        static GLOBAL_PATH_LOCKS: std::sync::OnceLock<
            std::sync::Arc<
                std::sync::Mutex<
                    HashMap<std::path::PathBuf, std::sync::Arc<std::sync::Mutex<()>>>,
                >,
            >,
        > = std::sync::OnceLock::new();
        let table = GLOBAL_PATH_LOCKS
            .get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())));
        let mut map = table.lock().unwrap_or_else(|e| e.into_inner());
        // Long-running HTTP services accumulate paths over time: when the table grows too large,
        // drop locks nobody holds (an Arc strong count of 1 means only this table references it, so removal is safe)
        if map.len() > 4096 {
            map.retain(|_, v| std::sync::Arc::strong_count(v) > 1);
        }
        map.entry(std::path::PathBuf::from(path))
            .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
            .clone()
    }

    /// Runs read-modify-write inside the "same-path serialization lock" to prevent multiple AIs from overwriting the same file concurrently.
    /// Two layers of locking:
    /// 1) in-process lock (multiple sessions in one process under HTTP mode);
    /// 2) cross-process lock file (under stdio mode each AI is a separate process, the in-process lock is ineffective, a lock file is required).
    fn with_path_lock<T, F: FnOnce() -> Result<T, McpError>>(
        &self,
        path: &str,
        f: F,
    ) -> Result<T, McpError> {
        let lock = self.lock_for(path);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_guard = Self::acquire_file_lock(path);
        f()
    }

    /// Cross-process lock: creates `<file>.file-io-mcp.lock` next to the target file; a successful create_new acquires the lock.
    /// If it can't be obtained, wait and retry; on timeout or failure to create (read-only dir, etc.) degrade to no lock, favoring availability.
    fn acquire_file_lock(path: &str) -> FileLockGuard {
        const WAIT_MS: u64 = 50;
        const MAX_WAIT_MS: u64 = 10_000;
        const STALE_MS: u128 = 30_000; // 持有者崩溃留下的死锁超过该时长则强制抢占

        let lock_path = std::path::PathBuf::from(format!("{}.file-io-mcp.lock", path));
        let mut waited = 0u64;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    let _ = f.write_all(format!("pid={}", std::process::id()).as_bytes());
                    return FileLockGuard { path: lock_path };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // a lock file left behind by a crashed owner; forcibly seize it after it goes stale
                    if Self::is_stale_lock(&lock_path, STALE_MS) {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    if waited >= MAX_WAIT_MS {
                        // favor availability: after waiting too long, stop blocking (expected_sha256 still backs us up)
                        return FileLockGuard { path: std::path::PathBuf::new() };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(WAIT_MS));
                    waited += WAIT_MS;
                }
                Err(_) => {
                    // 无法创建锁文件（目录不可写等）：降级为无锁
                    return FileLockGuard { path: std::path::PathBuf::new() };
                }
            }
        }
    }

    /// 锁文件是否过期（持有进程可能已崩溃）
    fn is_stale_lock(lock_path: &std::path::Path, stale_ms: u128) -> bool {
        match fs::metadata(lock_path).and_then(|m| m.modified()) {
            Ok(t) => match t.elapsed() {
                Ok(d) => d.as_millis() > stale_ms,
                Err(_) => true,
            },
            Err(_) => true,
        }
    }

    /// Validate and resolve the path, ensuring it stays within the root sandbox (if root is configured).
    /// The returned value is used for both **filesystem operations** and **echoing back**, so it must:
    /// 1) be stable: all spellings of the same file (relative/absolute/with `..`/different case) map to one string,
    ///    otherwise lock keys and backup partitions would split (backup key also see `backup_path_key`, which re-normalizes by absolute form);
    /// 2) be readable: files **under the current directory** echo a relative path (e.g. `src\main.rs`),
    ///    others echo an absolute path with the `\\?\` prefix stripped (`\\?\F:\a` → `F:\a`).
    /// Relative spelling must be based on the current directory -- that is how the filesystem layer resolves relative paths;
    /// if you echo based on another root (e.g. sandbox root), the echoed relative path would be written elsewhere.
    fn resolve_path(&self, path: &str) -> Result<String, McpError> {
        let cwd = std::env::current_dir()
            .map_err(|e| e_internal(format!("cannot get current directory: {}", e), None))?;

        let p = std::path::Path::new(path);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };

        // First resolve to an as-real-as-possible path: the longest existing prefix is OS-canonicalized (unifies case, expands 8.3 short names,
        // resolves symlinks/junctions), and the non-existing tail is appended as-is; fall back to textual normalization when unsafe to resolve.
        // This way a path inside root but spelled differently is not wrongly rejected by substring comparison, while out-of-bounds/link escapes are still blocked.
        let resolved = Self::resolve_existing_prefix(&abs);

        if let Some(r) = &self.root {
            if !Self::sandbox_within(&resolved, r) {
                return Err(e_param(
                    format!(
                        "path is outside the allowed root: {} (root: {})",
                        path,
                        r.display()
                    ),
                    None,
                ));
            }
        }

        Ok(Self::display_path(&resolved, &cwd))
    }

    /// Strip the Windows extended-length prefix: `\\?\F:\a` → `F:\a`, `\\?\UNC\srv\share\a` → `\\srv\share\a`.
    /// The `\\?\` form is hard to read, disables later path normalization, and is unsuitable to echo back to the caller.
    fn strip_verbatim_prefix(p: &std::path::Path) -> std::path::PathBuf {
        let s = p.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return std::path::PathBuf::from(format!(r"\\{}", rest));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return std::path::PathBuf::from(rest);
        }
        p.to_path_buf()
    }

    /// Build the echoed path: when under base (current directory) return the relative spelling, otherwise return the absolute path with the `\\?\` prefix stripped.
    /// base must be the current directory, so that when the caller passes the echoed relative path back it resolves correctly.
    /// The input must be an already-normalized absolute path (no `.`/`..`).
    fn display_path(resolved: &std::path::Path, base: &std::path::Path) -> String {
        let plain = Self::strip_verbatim_prefix(resolved);
        let base_plain = Self::strip_verbatim_prefix(base);
        match plain.strip_prefix(&base_plain) {
            // this is the base directory itself
            Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
            Ok(rel) => rel.to_string_lossy().into_owned(),
            Err(_) => plain.to_string_lossy().into_owned(),
        }
    }

    /// Decide whether an IO error is cross-device/cross-volume (Windows ERROR_NOT_SAME_DEVICE=17, Unix EXDEV=18),
    /// used to fall back a move to "copy + delete".
    fn is_cross_device_error(e: &std::io::Error) -> bool {
        // 17/18 are each platform's own "cross-device" error code; their meanings are not interchangeable:
        // Windows ERROR_NOT_SAME_DEVICE=17; Unix EXDEV=18.
        // If 18 were treated as cross-device on Windows, ERROR_NO_MORE_FILES(18) would be misjudged as cross-volume.
        #[cfg(windows)]
        {
            matches!(e.raw_os_error(), Some(17))
        }
        #[cfg(not(windows))]
        {
            matches!(e.raw_os_error(), Some(18))
        }
    }

    /// Whether a path is under the sandbox root (root itself included). Compared by **path components**,
    /// so that "C:\data" does not let a same-prefix "C:\data-evil" through as an in-root path.
    fn sandbox_within(path: &std::path::Path, root: &std::path::Path) -> bool {
        let p = std::path::PathBuf::from(Self::sandbox_cmp_key(path));
        let r = std::path::PathBuf::from(Self::sandbox_cmp_key(root));
        p.starts_with(&r)
    }

    /// Decide whether target is a directory or a file path (resolved = resolved absolute path, raw = caller's original input):
    /// - target exists: use the filesystem's actual type
    /// - target does not exist: a directory for multiple sources; a new file path (rename allowed) for a single source,
    ///   unless the raw input ends with `/` or `\` (explicitly meaning "put into a directory")
    fn target_is_dir_for(resolved: &std::path::Path, raw: &str, source_count: usize) -> bool {
        if resolved.exists() {
            return resolved.is_dir();
        }
        if source_count > 1 {
            return true;
        }
        let t = raw.trim_end();
        t.ends_with('/') || t.ends_with('\\')
    }

    /// Sampling for encoding detection: prefer the **full file content**; when the read window this time is not the full file,
    /// re-read the whole file (only the head for files over MAX_TEXT_READ_SIZE) for detection,
    /// to avoid misdetecting the encoding because the window was truncated mid multi-byte character.
    fn encoding_probe_bytes(
        path: &str,
        window_start: u64,
        window_truncated: bool,
        window: &[u8],
    ) -> Result<Vec<u8>, String> {
        // a non-empty window is what makes "this window is the full file"; otherwise (e.g. length=0) an empty sample is detected as utf-8,
        // which would also report a GBK file as utf-8.
        if window_start == 0 && !window_truncated && !window.is_empty() {
            return Ok(window.to_vec());
        }
        let size = fs::metadata(path)
            .map_err(|e| format!("failed to read file: {}", e))?
            .len();
        if size <= MAX_TEXT_READ_SIZE as u64 {
            let bytes = fs::read(path).map_err(|e| format!("failed to read file: {}", e))?;
            Ok(Self::utf8_trim_incomplete_tail(&bytes).to_vec())
        } else {
            let mut f = File::open(path).map_err(|e| format!("failed to open file: {}", e))?;
            let mut head = vec![0u8; MAX_TEXT_READ_SIZE];
            f.read_exact(&mut head)
                .map_err(|e| format!("failed to read file: {}", e))?;
            Ok(Self::utf8_trim_incomplete_tail(&head).to_vec())
        }
    }

    /// For encoding-detection sampling: if the slice's only problem is "a trailing incomplete multi-byte character", cut to the last complete character;
    /// when there are genuinely invalid bytes, keep it as-is and let the detection logic judge it non-UTF-8 text.
    fn utf8_trim_incomplete_tail(bytes: &[u8]) -> &[u8] {
        match std::str::from_utf8(bytes) {
            Ok(_) => bytes,
            Err(e) if e.error_len().is_none() => &bytes[..e.valid_up_to()],
            Err(_) => bytes,
        }
    }

    /// Path key for sandbox comparison: normalize (strip `\\?\`, fold `.`/`..`) + lowercase.
    /// Windows paths are case-insensitive, so `F:\A` and `f:\a` must be treated as the same path.
    fn sandbox_cmp_key(p: &std::path::Path) -> String {
        let s = normalize_path(p).to_string_lossy().into_owned();
        // Only Windows paths are case-insensitive; keep Unix case-sensitive to avoid mistaking two different paths as one
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s
        }
    }

    /// Build the most-real absolute path from "the longest canonicalizable prefix + the non-existing tail".
    /// - target exists: equivalent to canonicalize (case/short-name/symlink all resolved by OS)
    /// - target does not exist (e.g. a new file): locate the nearest existing ancestor and re-append the tail, avoiding a full fallback to textual comparison
    /// - tail contains `..` or other special segments, or the whole path is unresolvable: fall back to normalize_path's textual form
    fn resolve_existing_prefix(p: &std::path::Path) -> std::path::PathBuf {
        use std::path::Component;
        let comps: Vec<Component> = p.components().collect();
        for split in (1..=comps.len()).rev() {
            let tail = &comps[split..];
            // the tail accepts only plain segments: when it contains `..`/`.`/prefix segments, use a shorter split so they enter the canonicalizable prefix
            if tail.iter().any(|c| !matches!(c, Component::Normal(_))) {
                continue;
            }
            let prefix: std::path::PathBuf = comps[..split].iter().collect();
            if let Ok(canon) = prefix.canonicalize() {
                let mut out = canon;
                for c in tail {
                    if let Component::Normal(n) = c {
                        out.push(n);
                    }
                }
                return out;
            }
        }
        normalize_path(p)
    }

    /// Lenient HEX parsing: allows a 0x prefix and space/colon/comma/dash separators (so you can paste straight from a hex dump)
    fn parse_hex_flexible(s: &str) -> Result<Vec<u8>, String> {
        let trimmed = s.trim();
        let body = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let cleaned: String = body
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && !matches!(c, ':' | ',' | '-' | '_'))
            .collect();
        // empty content is treated as 0 bytes (whether allowed is up to the caller: write_binary_file's replace uses it to delete bytes)
        if cleaned.is_empty() {
            return Ok(Vec::new());
        }
        if !cleaned.len().is_multiple_of(2) {
            return Err(format!(
                "length is {} hex chars (odd); each byte needs two digits",
                cleaned.len()
            ));
        }
        let bad: String = cleaned
            .chars()
            .filter(|c| !c.is_ascii_hexdigit())
            .collect();
        if !bad.is_empty() {
            return Err(format!("contains invalid char(s): [{}]; only 0-9, A-F, a-f allowed", bad));
        }
        (0..cleaned.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .map_err(|e| format!("parse failed: {}", e))
            })
            .collect()
    }

    /// Get the actual bytes of the "range to change" plus a range description, for expected_hex verification.
    /// Deliberately no clamp/pad: out-of-range returns a short/empty slice, which is then necessarily judged as a mismatch.
    fn binary_guard_range(
        cur: &[u8],
        mode: &str,
        offset: Option<u64>,
        replace_length: Option<usize>,
        expect_len: usize,
    ) -> (Vec<u8>, String) {
        match mode {
            "append" => {
                let start = cur.len().saturating_sub(expect_len);
                (cur[start..].to_vec(), "end of file (append point)".to_string())
            }
            "insert" => {
                let off = (offset.unwrap_or(0) as usize).min(cur.len());
                let end = off.saturating_add(expect_len).min(cur.len());
                (cur[off..end].to_vec(), format!("insert point offset={}", off))
            }
            "replace" => {
                let off = offset.unwrap_or(0) as usize;
                let len = replace_length.unwrap_or(0);
                if off >= cur.len() {
                    return (Vec::new(), format!("[{}..{}) out of range", off, off.saturating_add(len)));
                }
                let end = off.saturating_add(len).min(cur.len());
                (cur[off..end].to_vec(), format!("[{}..{})", off, end))
            }
            _ => (cur.to_vec(), "entire file".to_string()),
        }
    }

    /// HEX preview: space-separated uppercase bytes, truncated when too long to avoid flooding the output
    fn hex_preview(bytes: &[u8]) -> String {
        const MAX_SHOW: usize = 128;
        if bytes.is_empty() {
            return String::new();
        }
        let shown: Vec<String> = bytes
            .iter()
            .take(MAX_SHOW)
            .map(|b| format!("{:02X}", b))
            .collect();
        if bytes.len() > MAX_SHOW {
            format!(
                "{} ... ({} bytes total, first {} shown)",
                shown.join(" "),
                bytes.len(),
                MAX_SHOW
            )
        } else {
            shown.join(" ")
        }
    }

    /// dry_run preview: only output the changed window (capped) plus before/after size and fingerprint, without writing the file
    fn binary_dry_run_report(path: &str, old: &[u8], new: &[u8], action: &str) -> String {
        const CTX: usize = 16;
        const MAX_SHOW: usize = 256;
        let max_len = old.len().max(new.len());
        let mut first: Option<usize> = None;
        let mut last = 0usize;
        let mut changed = 0usize;
        for i in 0..max_len {
            if old.get(i) != new.get(i) {
                if first.is_none() {
                    first = Some(i);
                }
                last = i;
                changed += 1;
            }
        }

        let mut out = format!(
            "[DRY-RUN] {} | {} | {}B→{}B | sha256:{}→{}\nnot written to disk (remove dry_run or pass dry_run=false to execute)",
            path,
            action,
            old.len(),
            new.len(),
            Self::fingerprint_short_of_bytes(old),
            Self::fingerprint_short_of_bytes(new)
        );

        let Some(f) = first else {
            out.push_str("\ncontent unchanged");
            return out;
        };

        let win_start = f.saturating_sub(CTX);
        let win_end = (last + 1 + CTX).min(max_len);
        let show_end = (win_start + MAX_SHOW).min(win_end);
        let take = |data: &[u8]| -> Vec<u8> {
            let end = show_end.min(data.len());
            if win_start >= end {
                Vec::new()
            } else {
                data[win_start..end].to_vec()
            }
        };
        out.push_str(&format!(
            "\ndiff window [{}, {}) : {} bytes differ{}",
            win_start,
            win_end,
            changed,
            if show_end < win_end {
                format!("(window too long, showing first {} bytes)", MAX_SHOW)
            } else {
                String::new()
            }
        ));
        out.push_str(&format!(
            "\n  old @{:08X}: {}",
            win_start,
            Self::hex_preview(&take(old))
        ));
        out.push_str(&format!(
            "\n  new @{:08X}: {}",
            win_start,
            Self::hex_preview(&take(new))
        ));
        out
    }

    /// Ensure the file's parent directory exists; create it automatically if not
    fn ensure_parent_dir(path: &str) -> Result<(), String> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.exists() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
            }
        }
        Ok(())
    }

    /// Validate and canonicalize the encoding name: UTF-32 is not in encoding_rs, so it is handled by the built-in implementation and must be allowed separately.
    fn canonical_encoding(name: &str) -> Result<&'static str, String> {
        match name.to_ascii_lowercase().as_str() {
            "utf-32le" => Ok("utf-32le"),
            "utf-32be" => Ok("utf-32be"),
            _ => Ok(Self::get_encoding(name)?.name()),
        }
    }

    /// Get the encoding_rs Encoding reference by encoding name
    fn get_encoding(name: &str) -> Result<&'static encoding_rs::Encoding, String> {
        encoding_rs::Encoding::for_label(name.as_bytes())
            .ok_or_else(|| format!("unsupported encoding: {}. supported encodings include: utf-8, gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr, utf-16le, utf-16be, iso-8859-1, etc.", name))
    }

    /// Decode bytes into a string with the given encoding
    fn decode_bytes(bytes: &[u8], encoding_name: &str) -> Result<String, String> {
        let encoding = Self::get_encoding(encoding_name)?;
        let (cow, _encoding_used, had_errors) = encoding.decode(bytes);
        if had_errors {
            Err(format!("failed to decode with {}; data may contain invalid bytes", encoding_name))
        } else {
            Ok(cow.into_owned())
        }
    }

    /// Encode a string into bytes with the given encoding
    fn encode_string(s: &str, encoding_name: &str) -> Result<Vec<u8>, String> {
        let encoding = Self::get_encoding(encoding_name)?;
        let (cow, _encoding_used, had_errors) = encoding.encode(s);
        if had_errors {
            Err(format!("failed to encode with {}; the string contains characters not representable in this encoding", encoding_name))
        } else {
            Ok(cow.into_owned())
        }
    }

    /// Detect the BOM bytes at the file head; return an empty slice when there is no BOM.
    /// Used together with detect_encoding; restored verbatim on write-back to avoid BOM loss corrupting the encoding.
    fn detect_bom(bytes: &[u8]) -> &'static [u8] {
        if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            return &[0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        }
        if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xFE && bytes[2] == 0x00 && bytes[3] == 0x00 {
            return &[0xFF, 0xFE, 0x00, 0x00]; // UTF-32LE BOM
        }
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            return &[0xFF, 0xFE]; // UTF-16LE BOM
        }
        if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
            return &[0xFE, 0xFF]; // UTF-16BE BOM
        }
        if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0xFE && bytes[3] == 0xFF {
            return &[0x00, 0x00, 0xFE, 0xFF]; // UTF-32BE BOM
        }
        &[]
    }

    /// Auto-detect the file encoding (result only, confidence dropped)
    fn detect_encoding(bytes: &[u8]) -> &'static str {
        Self::detect_encoding_with_confidence(bytes).0
    }

    /// Auto-detect the file encoding and report a confidence flag.
    /// The core is to reliably tell GBK from UTF-8: you cannot only look at "是否合法 UTF-8",
    /// because some GBK Chinese byte sequences are also valid UTF-8 (they decode into Cyrillic/Arabic and come out garbled overall).
    /// Method: decode with both encodings, score each by "像不像中文文本", take the higher; mark low confidence when they are close.
    fn detect_encoding_with_confidence(bytes: &[u8]) -> (&'static str, bool) {
        // BOM detection (a BOM means it is certain)
        if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            return ("utf-8", true);
        }
        if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xFE && bytes[2] == 0x00 && bytes[3] == 0x00 {
            return ("utf-32le", true);
        }
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            return ("utf-16le", true);
        }
        if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
            return ("utf-16be", true);
        }
        if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0xFE && bytes[3] == 0xFF {
            return ("utf-32be", true);
        }

        // UTF-16 detection without BOM must come before the UTF-8 check:
        // UTF-16LE ASCII text alternates "ASCII 字节 + 0x00"; but 0x00 is a valid character in UTF-8,
        // so checking UTF-8 first would misjudge it as utf-8 and read screenfuls of NUL "garbage".
        // For large files only look at the first 64KB (the NUL-alternation pattern of UTF-16 is obvious at the start)
        let probe: &[u8] = if bytes.len() > 64 * 1024 {
            &bytes[..64 * 1024]
        } else {
            bytes
        };
        if let Some(enc) = Self::detect_utf16_without_bom(probe) {
            return (enc, true);
        }

        // Pure ASCII: UTF-8 and GBK bytes are identical, so judging it utf-8 is risk-free
        if bytes.is_empty() || bytes.iter().all(|b| *b < 0x80) {
            return ("utf-8", true);
        }

        // UTF-8 vs GBK scoring (invalid UTF-8 scores negative infinity).
        // For large files only score a head sample: the encoding features show clearly enough on the sample,
        // while fully decoding a 5MB Chinese file twice would cost tens of milliseconds
        const SAMPLE_LIMIT: usize = 256 * 1024;
        let sample: &[u8] = if bytes.len() > SAMPLE_LIMIT {
            let raw = &bytes[..SAMPLE_LIMIT];
            // Step back to a UTF-8 character boundary: a half character at the cut would make UTF-8 parsing fail and disturb scoring
            let mut end = raw.len();
            while end > 0 && (raw[end - 1] & 0xC0) == 0x80 {
                end -= 1;
            }
            if end > 0 {
                end -= 1;
            }
            if end < 16 {
                bytes
            } else {
                &raw[..end]
            }
        } else {
            bytes
        };
        // Invalid-byte detection must be full-file (so bad bytes in the middle are not missed); scoring uses the sample
        let s_utf8 = match std::str::from_utf8(bytes) {
            Ok(_) => Self::text_likelihood(std::str::from_utf8(sample).unwrap_or("")),
            Err(_) => f64::NEG_INFINITY,
        };
        let s_gbk = Self::text_likelihood(
            &encoding_rs::Encoding::for_label(b"gbk").unwrap().decode(sample).0,
        );

        // Structurally valid UTF-8 is a strong signal: as long as the full UTF-8 check passes and the score is not below GBK (allowing GBK to lead by <=0.02
        // of noise), judge it UTF-8 with **high confidence**.
        // Do not use "两候选分数差足够大" as a deterministic condition -- e.g. UTF-8 source where pure ASCII dominates,
        // decodes just as smoothly with GBK; both scores are near 1.0 with a tiny gap, and would be falsely reported as "编码识别不确定".
        // Only consider GBK when its score is clearly higher (leads by >0.02); and it counts as high confidence only when it leads by >=0.1.
        let (best, best_score, confident) = if s_utf8.is_finite() && s_gbk <= s_utf8 + 0.02 {
            ("utf-8", s_utf8, true)
        } else {
            // 走到这里说明 s_gbk > s_utf8（含 s_utf8 为负无穷，即非法 UTF-8）
            ("gbk", s_gbk, s_gbk - s_utf8 >= 0.1)
        };

        // When neither candidate looks like normal text, try other CJK encodings and take the highest-scoring one (marked low confidence).
        // Again score only the sample here, to avoid decoding the whole file under 4 encodings just for detection.
        if !(best_score >= 0.85) {
            let mut alt = (best, best_score);
            for &enc in &["big5", "euc-kr", "shift_jis", "euc-jp"] {
                let s = Self::text_likelihood(
                    &encoding_rs::Encoding::for_label(enc.as_bytes()).unwrap().decode(sample).0,
                );
                if s > alt.1 {
                    alt = (enc, s);
                }
            }
            return (alt.0, false);
        }

        (best, confident)
    }

    /// Score of how much the decoded text "像不像中文文本" (0.0~1.0):
    /// CJK and full-width characters add points; replacement/control/unrelated-script characters subtract.
    /// Used to tell GBK from UTF-8: text decoded with the wrong encoding is usually full of unexpected characters, so its score is clearly lower.
    fn text_likelihood(s: &str) -> f64 {
        let mut good = 0.0f64;
        let mut bad = 0.0f64;
        for c in s.chars() {
            match c {
                // CJK ideographs (strong signal for Chinese text)
                '\u{4E00}'..='\u{9FFF}' => good += 2.0,
                // CJK punctuation and full-width characters (common in GBK text)
                '\u{3000}'..='\u{303F}' | '\u{FF00}'..='\u{FFEF}' => good += 2.0,
                // Whitespace and printable ASCII
                '\t' | '\r' | '\n' | '\u{20}'..='\u{7E}' => good += 1.0,
                // Replacement char: means there are bytes the encoding cannot represent
                '\u{FFFD}' => bad += 5.0,
                // Other control characters
                c if c.is_control() => bad += 5.0,
                // Other scripts (Cyrillic, Arabic, kana, etc.) and rare symbols: should not appear in a Chinese file
                _ => bad += 1.0,
            }
        }
        let total = good + bad;
        if total <= 0.0 {
            return 0.0;
        }
        good / total
    }

    /// Check whether byte offset off lands on a character boundary for this encoding (used by insert operations, to avoid splitting a character)
    fn is_char_boundary(encoding: &str, bytes: &[u8], off: usize) -> bool {
        if off == 0 || off >= bytes.len() {
            return true;
        }
        match encoding.to_ascii_lowercase().as_str() {
            // UTF-8 continuation bytes look like 10xxxxxx
            "utf-8" => (bytes[off] & 0xC0) != 0x80,
            // UTF-16 aligns to 2 bytes, UTF-32 to 4 bytes (surrogate pairs are not validated, which is enough and avoids false rejections)
            "utf-16le" | "utf-16be" => off % 2 == 0,
            "utf-32le" | "utf-32be" => off % 4 == 0,
            // Single-byte encodings (iso-8859-1/latin1, windows-125x, koi8-r, etc.): any offset is a character boundary
            n if Self::is_single_byte_encoding(n) => true,
            // Double-byte encodings like GBK/Big5: walk character by character from the file head by "ASCII single byte / double-byte char",
            // and see whether it stops exactly at off.
            // Must not start from "the nearest ASCII byte": a GBK double-byte's second byte can also fall in the ASCII range
            // (0x40-0x7E), which would mistake the inside of a character for a boundary and insert/cut a multi-byte character in the middle.
            _ => {
                let mut pos = 0usize;
                while pos < off {
                    match Self::legacy_char_advance(encoding, bytes, pos) {
                        Some(next) => pos = next,
                        None => {
                            // Invalid/orphan byte, cannot judge reliably -> allow (better to not block than to block wrongly)
                            return true;
                        }
                    }
                }
                pos == off
            }
        }
    }

    /// Floor a byte offset to the character boundary of this encoding (only for encodings whose boundary is cheap to determine; return as-is when it cannot be).
    /// `byte_at_off`: the first byte at the offset (passed by the caller when the window is already read), used to tell whether UTF-8 lands exactly on a boundary.
    fn floor_char_boundary(encoding: &str, path: &str, off: u64, byte_at_off: Option<u8>) -> u64 {
        if off == 0 {
            return 0;
        }
        match encoding.to_ascii_lowercase().as_str() {
            "utf-16le" | "utf-16be" => off - (off % 2),
            "utf-32le" | "utf-32be" => off - (off % 4),
            "utf-8" => {
                // UTF-8 continuation bytes look like 10xxxxxx; if off is already a lead byte, it is on the boundary
                if let Some(b) = byte_at_off {
                    if (b & 0xC0) != 0x80 {
                        return off;
                    }
                }
                // Look back at most 3 bytes to find the nearest non-continuation byte position before off
                let back = off.min(3) as usize;
                if back == 0 {
                    return 0;
                }
                let mut f = match File::open(path) {
                    Ok(f) => f,
                    Err(_) => return off,
                };
                if f.seek(SeekFrom::Start(off - back as u64)).is_err() {
                    return off;
                }
                let mut buf = vec![0u8; back];
                if f.read_exact(&mut buf).is_err() {
                    return off;
                }
                for k in 1..=back {
                    if (buf[back - k] & 0xC0) != 0x80 {
                        return off - k as u64;
                    }
                }
                off
            }
            // Single-byte encoding: each byte is a character, so the boundary is off itself
            n if Self::is_single_byte_encoding(n) => off,
            _ => {
                // GBK/Big5/GB18030 etc.: the boundary must be found by walking character by character from the head (O(off)).
                // When off is too large it is not worth reading the whole prefix, so return as-is; otherwise read [0, off+4) and walk,
                // to find the nearest boundary <= off (a character is at most 4 bytes, usually only 1~3 bytes of backtrack).
                const MAX_WALK: u64 = 4 * 1024 * 1024;
                if off > MAX_WALK {
                    return off;
                }
                let want = (off + 4) as usize;
                let f = match File::open(path) {
                    Ok(f) => f,
                    Err(_) => return off,
                };
                let mut buf: Vec<u8> = Vec::with_capacity(want);
                if f.take(want as u64).read_to_end(&mut buf).is_err() {
                    return off;
                }
                if buf.len() < off as usize {
                    return off;
                }
                let mut pos = 0usize;
                let mut boundary = 0usize;
                while pos < off as usize {
                    boundary = pos;
                    match Self::legacy_char_advance(encoding, &buf, pos) {
                        Some(next) => pos = next,
                        None => return off,
                    }
                }
                if pos == off as usize {
                    off
                } else {
                    boundary as u64
                }
            }
        }
    }

    /// Under single-byte / double-byte (GB18030 includes 4-byte) encodings, "advance one character" and return the next character's start position.
    /// Return None on an invalid or orphan byte (boundary cannot be judged reliably).
    fn legacy_char_advance(encoding: &str, bytes: &[u8], pos: usize) -> Option<usize> {
        let b = *bytes.get(pos)?;
        if b < 0x80 {
            return Some(pos + 1);
        }
        // GB18030 四字节序列：首 0x81-0xFE，次 0x30-0x39，三 0x81-0xFE，四 0x30-0x39
        if encoding.eq_ignore_ascii_case("gb18030")
            && pos + 3 < bytes.len()
            && (0x81..=0xFE).contains(&b)
            && (0x30..=0x39).contains(&bytes[pos + 1])
            && (0x81..=0xFE).contains(&bytes[pos + 2])
            && (0x30..=0x39).contains(&bytes[pos + 3])
        {
            return Some(pos + 4);
        }
        if (0x81..=0xFE).contains(&b) {
            return Some(pos + 2);
        }
        None
    }

    /// Whether this is a single-byte encoding (iso-8859-1/latin1, windows-125x, koi8-r, macintosh, etc.).
    /// In these encodings each byte is one character, so every offset is a character boundary;
    /// mis-aligning with GBK's double-byte rule would push a valid position like offset=1 back to 0 (wrong content and location).
    fn is_single_byte_encoding(name: &str) -> bool {
        Self::get_encoding(name)
            .map(|e| e.is_single_byte())
            .unwrap_or(false)
    }

    /// Count newlines from the start of the file up to `upto` bytes (read in chunks to avoid allocating the whole prefix for large offsets).
    fn count_newlines_before(file: &mut File, upto: u64) -> std::io::Result<usize> {
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = upto;
        let mut buf = vec![0u8; 64 * 1024];
        let mut count = 0usize;
        while remaining > 0 {
            let want = (remaining.min(buf.len() as u64)) as usize;
            let n = file.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            count += buf[..n].iter().filter(|&&b| b == b'\n').count();
            remaining -= n as u64;
        }
        Ok(count)
    }

    /// The BOM that this encoding should carry when creating a new file. UTF-16/32 must include a BOM to be re-recognized later,
    /// otherwise detect_encoding would misjudge it as GBK; UTF-8 etc. stay BOM-less (preserving current behavior).
    fn default_bom_for(encoding: &str) -> &'static [u8] {
        match encoding.to_ascii_lowercase().as_str() {
            "utf-16le" => &[0xFF, 0xFE],
            "utf-16be" => &[0xFE, 0xFF],
            "utf-32le" => &[0xFF, 0xFE, 0x00, 0x00],
            "utf-32be" => &[0x00, 0x00, 0xFE, 0xFF],
            _ => &[],
        }
    }

    /// Detect BOM-less UTF-16:
    /// - LE: even index is non-zero ASCII, odd index is mostly 0x00 (e.g. 75 00 6E 00)
    /// - BE: the reverse (e.g. 00 75 00 6E)
    /// Only decide when the pattern is strong enough, to avoid misclassifying binary/GBK files containing a few NULs as UTF-16.
    fn detect_utf16_without_bom(bytes: &[u8]) -> Option<&'static str> {
        if bytes.len() < 4 || bytes.len() % 2 != 0 {
            return None;
        }
        let pairs = bytes.len() / 2;
        let mut le_hits = 0usize;
        let mut be_hits = 0usize;
        for i in 0..pairs {
            let a = bytes[i * 2];
            let b = bytes[i * 2 + 1];
            if a != 0 && b == 0 {
                le_hits += 1;
            } else if a == 0 && b != 0 {
                be_hits += 1;
            }
        }
        // At least 90% of code units match the pattern, and the sample is large enough
        let threshold = pairs * 9 / 10;
        if pairs >= 4 && le_hits >= threshold && le_hits > be_hits {
            return Some("utf-16le");
        }
        if pairs >= 4 && be_hits >= threshold && be_hits > le_hits {
            return Some("utf-16be");
        }
        None
    }

    /// Whether the encoding parameter means "auto-detect": absent / empty string / "auto" all count.
    /// The three read tools previously handled empty strings inconsistently (read_text_file treated it as auto, read_text_lines errored,
    /// text_search skipped the whole file); now they all go through here.
    fn encoding_is_auto(enc: Option<&str>) -> bool {
        enc.map_or(true, |e| e.is_empty() || e.eq_ignore_ascii_case("auto"))
    }

    /// Resolve the encoding parameter, returning (encoding, confidence):
    /// on "auto"/unspecified, auto-detect and report confidence; an explicit value is treated as high-confidence. Validates the encoding.
    /// Low confidence means "GBK/UTF-8 are hard to tell apart", so read tools should prompt the AI to specify encoding explicitly
    fn resolve_encoding_with_confidence(
        param: Option<&str>,
        bytes: &[u8],
    ) -> Result<(&'static str, bool), String> {
        match param {
            Some(name) if !Self::encoding_is_auto(Some(name)) => {
                Ok((Self::canonical_encoding(name)?, true))
            }
            _ => Ok(Self::detect_encoding_with_confidence(bytes)),
        }
    }

    /// Compute the SHA256 hex of the bytes
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

    /// Version fingerprint algorithm (**single source of truth**; reads, writes and file_info all go through here):
    /// - ≤1MB: sha256 of the whole content
    /// - >1MB: sha256("size + head 64KB + tail 64KB"), to avoid reading the entire large file just to compute the sha
    fn fingerprint_of_bytes(bytes: &[u8]) -> String {
        const INLINE_MAX: usize = 1024 * 1024;
        const SAMPLE: usize = 64 * 1024;
        if bytes.len() <= INLINE_MAX {
            return Self::sha256_hex(bytes);
        }
        let take = SAMPLE.min(bytes.len());
        let mut buf: Vec<u8> = Vec::with_capacity(take * 2 + 8);
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&bytes[..take]);
        buf.extend_from_slice(&bytes[bytes.len() - take..]);
        Self::sha256_hex(&buf)
    }

    /// Version fingerprint (use this when the full content is already in memory; bytes must be the file's complete content).
    /// Write tools **must** use this to compute the sha256 returned to the AI, rather than reading the disk right after writing:
    /// on Windows, reading immediately after a rename replacement may still read a stale cached page, returning a fingerprint that
    /// does not match the actual content, causing the AI to be falsely told "the file was modified" when using it as expected_sha256.
    fn fingerprint_short_of_bytes(bytes: &[u8]) -> String {
        let h = Self::fingerprint_of_bytes(bytes);
        h[..16].to_string()
    }

    /// Get the full version fingerprint by path; for large files only read head and tail of 64KB each
    fn file_fingerprint(path: &str, size: u64, bytes: Option<&[u8]>) -> Option<String> {
        const INLINE_MAX: u64 = 1024 * 1024;
        const SAMPLE: usize = 64 * 1024;
        // When the caller already holds the full content, compute in memory directly regardless of size (fingerprint_of_bytes samples head/tail internally for large files),
        // to avoid reading the large file from disk again just for the fingerprint
        if let Some(b) = bytes {
            if b.len() as u64 == size {
                return Some(Self::fingerprint_of_bytes(b));
            }
        }
        if size <= INLINE_MAX {
            return fs::read(path).ok().map(|b| Self::fingerprint_of_bytes(&b));
        }
        // Large file: assemble "size + head + tail" in the same order as fingerprint_of_bytes
        let mut f = File::open(path).ok()?;
        let take = SAMPLE.min(size as usize);
        let mut buf: Vec<u8> = Vec::with_capacity(take * 2 + 8);
        buf.extend_from_slice(&size.to_le_bytes());
        let mut head = vec![0u8; take];
        f.read_exact(&mut head).ok()?;
        buf.extend_from_slice(&head);
        f.seek(SeekFrom::End(-(take as i64))).ok()?;
        let mut tail = vec![0u8; take];
        f.read_exact(&mut tail).ok()?;
        buf.extend_from_slice(&tail);
        Some(Self::sha256_hex(&buf))
    }

    /// Get the version fingerprint (first 16 chars, returned to the AI) for a path; returns "-" on failure
    fn path_fingerprint_short(path: &str) -> String {
        let size = match fs::metadata(path) {
            Ok(m) if m.is_file() => m.len(),
            _ => return "-".to_string(),
        };
        match Self::file_fingerprint(path, size, None) {
            Some(h) => h[..16].to_string(),
            None => "-".to_string(),
        }
    }

    /// Find all (non-overlapping) occurrences of needle in hay, returning (start, end) byte ranges.
    /// When both sides are valid UTF-8, the match start must land on a character boundary and is safe to slice.
    fn find_all(hay: &str, needle: &str) -> Vec<(usize, usize)> {
        if needle.is_empty() {
            return Vec::new();
        }
        hay.match_indices(needle)
            .map(|(i, m)| (i, i + m.len()))
            .collect()
    }

    /// The 1-based line number for a byte offset (used to explain "where the hit is")
    fn line_of(hay: &str, offset: usize) -> usize {
        // 调用方不能保证 offset 落在字符边界上（落在多字节字符中间很常见），
        // 这里向下取整到最近的边界后再切片，避免直接 panic
        let off = offset.min(hay.len());
        let off = (0..=off).rev().find(|i| hay.is_char_boundary(*i)).unwrap_or(0);
        hay[..off].matches('\n').count() + 1
    }

    /// "Self-consistency" check for auto-detected encoding: if the detected encoding cannot losslessly decode the existing file at all,
    /// the detection is unreliable (typical case: a GBK file misjudged as UTF-8); writing on would corrupt the file into mojibake, so refuse.
    /// The explicit-encoding path need not call this (resolve_write_encoding already guarantees consistency with the original file).
    fn check_encoding_lossless(encoding_name: &str, existing: &[u8]) -> Result<(), McpError> {
        // For large files (> 8MB) only validate the head sample: decoding the whole file just wastes CPU on large files,
        // and encoding features already show at the file start. The slice must step back to a character boundary, otherwise a half character would be
        // treated as an invalid byte by decode_file, causing a normal file to be wrongly rejected.
        const ENC_CHECK_FULL_LIMIT: usize = 8 * 1024 * 1024;
        let probe: &[u8] = if existing.len() <= ENC_CHECK_FULL_LIMIT {
            existing
        } else {
            let mut cut = ENC_CHECK_FULL_LIMIT;
            while cut > 0 && !Self::is_char_boundary(encoding_name, existing, cut) {
                cut -= 1;
            }
            &existing[..cut]
        };
        let lossless = matches!(
            Self::decode_file(probe, encoding_name),
            Ok(ft) if !ft.has_invalid
        );
        if !lossless {
            return Err(e_param(
                format!(
                    "auto-detected encoding [{}] cannot losslessly decode the existing file; the detection is unreliable, so writing is refused to avoid corrupting the file.\
                     Use read_text_file to confirm the real encoding, then pass encoding explicitly and retry",
                    encoding_name
                ),
                None,
            ));
        }
        Ok(())
    }


    /// Count lines of a text file (same convention as read_text_lines: non-empty content split by '\n', "a\nb\n" counts as 3 lines; empty file counts 0).
    /// Returns None when the encoding cannot be recognized or contains invalid bytes (caller shows "-"), without guessing.
    fn count_lines_of(path: &str) -> Option<usize> {
        let bytes = fs::read(path).ok()?;
        let enc = Self::detect_encoding(&bytes);
        let ft = Self::decode_file(&bytes, enc).ok()?;
        if ft.has_invalid {
            return None;
        }
        if ft.content.is_empty() {
            Some(0)
        } else {
            Some(ft.content.matches('\n').count() + 1)
        }
    }


    /// Summarize the landing positions of a batch edit into one line, so the caller can verify "are these exactly the places I asked for".
    /// Line numbers are the **pre-change** original line numbers (effects of later sections are not accumulated), matching the indices of the passed edits.
    fn format_section_positions(planned: &[PlannedSection]) -> String {
        let items: Vec<String> = planned
            .iter()
            .map(|p| {
                if p.line_from == p.line_to {
                    format!("edits[{}] line {}", p.idx, p.line_from)
                } else {
                    format!("edits[{}] lines {}-{}", p.idx, p.line_from, p.line_to)
                }
            })
            .collect();
        format!("Change positions (pre-change line numbers): {}", items.join(", "))
    }


    /// Pre-write version check (optimistic concurrency): if expected_sha256 does not match the current content, the file was changed by another AI/program,
    /// so refuse this write to avoid "writing the whole file back from old content" wiping out others' changes. Prefix matching is supported.
    fn check_expected_sha(
        path: &str,
        current_bytes: &[u8],
        expected: Option<&str>,
    ) -> Result<(), McpError> {
        let Some(exp) = expected else {
            return Ok(());
        };
        let exp = exp.trim().to_ascii_lowercase();
        if exp.is_empty() || exp.len() < 8 {
            return Ok(());
        }
        // Same algorithm as the actual read tools (sampled fingerprint for large files)
        let actual = Self::file_fingerprint(path, current_bytes.len() as u64, Some(current_bytes))
            .unwrap_or_else(|| Self::fingerprint_of_bytes(current_bytes));
        if actual.starts_with(&exp) {
            return Ok(());
        }
        Err(e_param(
            format!(
                "E_EXTERNAL_CHANGED the file was modified, write refused!\nfile: {}\nsha256 when you read: {}\ncurrent actual sha256: {}\n\
                 Re-read with read_text_lines/read_text_file to get the latest content and sha256, then retry (you may change only your lines, keep the rest as the latest)",
                path,
                exp,
                &actual[..16]
            ),
            None,
        ))
    }

    /// Decode file bytes into FileText: strip and record the BOM, detect the dominant line-ending style.
    /// Strictly symmetric with encode_file, ensuring the BOM is not lost after writing back (UTF-16 files won't degrade into GBK mojibake).
    fn decode_file(bytes: &[u8], encoding_name: &str) -> Result<FileText, String> {
        let bom = Self::detect_bom(bytes);
        let body = &bytes[bom.len()..];
        let lower = encoding_name.to_ascii_lowercase();
        let (content, has_invalid) = if lower == "utf-16le" || lower == "utf-16be" {
            // Decode UTF-16 ourselves, to guarantee strict symmetry with encode
            (Self::decode_utf16(body, lower == "utf-16le")?, false)
        } else if lower == "utf-32le" || lower == "utf-32be" {
            // encoding_rs does not support UTF-32, so decode ourselves here too (strictly symmetric with encode)
            (Self::decode_utf32(body, lower == "utf-32le")?, false)
        } else if lower == "utf-8" {
            match std::str::from_utf8(body) {
                Ok(s) => (s.to_string(), false),
                Err(_) => (String::from_utf8_lossy(body).into_owned(), true),
            }
        } else {
            let encoding = Self::get_encoding(encoding_name)?;
            let (cow, _used, had_errors) = encoding.decode(body);
            if had_errors {
                return Err(format!("failed to decode with {}; data may contain invalid bytes", encoding_name));
            }
            (cow.into_owned(), false)
        };
        // A single pass counts both \n and \r\n (result identical to two matches calls),
        // avoiding two full string scans for large files
        let mut crlf_count = 0usize;
        let mut total_lf = 0usize;
        let mut prev_cr = false;
        for &b in content.as_bytes() {
            if b == b'\n' {
                total_lf += 1;
                if prev_cr {
                    crlf_count += 1;
                }
            }
            prev_cr = b == b'\r';
        }
        let line_ending: &'static str = if crlf_count * 2 > total_lf { "\r\n" } else { "\n" };
        Ok(FileText {
            encoding: encoding_name.to_string(),
            bom,
            line_ending,
            content,
            has_invalid,
        })
    }

    /// UTF-16 decode: assemble UTF-16 code units by byte order then convert to a string
    fn decode_utf16(body: &[u8], little_endian: bool) -> Result<String, String> {
        if body.len() % 2 != 0 {
            return Err("UTF-16 data has an odd byte count, cannot decode (file may be truncated)".to_string());
        }
        let units: Vec<u16> = body
            .chunks(2)
            .map(|c| {
                if little_endian {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units)
            .map_err(|_| "UTF-16 decode failed, data contains an invalid surrogate pair".to_string())
    }

    /// UTF-16 encode: write UTF-16 code units by byte order (no BOM; BOM is restored by encode_file based on the original file)
    fn encode_utf16(content: &str, little_endian: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(content.len() * 2 + 2);
        for unit in content.encode_utf16() {
            let b = if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            };
            out.extend_from_slice(&b);
        }
        out
    }

    /// UTF-32 decode: assemble u32 code points by byte order (encoding_rs does not support UTF-32, so implemented here)
    fn decode_utf32(body: &[u8], little_endian: bool) -> Result<String, String> {
        if body.len() % 4 != 0 {
            return Err("UTF-32 byte count is not a multiple of 4, cannot decode (file may be truncated)".to_string());
        }
        let mut out = String::with_capacity(body.len() / 4);
        for c in body.chunks(4) {
            let v = if little_endian {
                u32::from_le_bytes([c[0], c[1], c[2], c[3]])
            } else {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            };
            match char::from_u32(v) {
                Some(ch) => out.push(ch),
                None => return Err(format!("UTF-32 decode failed: 0x{:08X} is not a valid code point", v)),
            }
        }
        Ok(out)
    }

    /// UTF-32 encode: write u32 code points by byte order (no BOM; BOM is restored by encode_file based on the original file)
    fn encode_utf32(content: &str, little_endian: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(content.chars().count() * 4);
        for ch in content.chars() {
            let b = if little_endian {
                (ch as u32).to_le_bytes()
            } else {
                (ch as u32).to_be_bytes()
            };
            out.extend_from_slice(&b);
        }
        out
    }

    /// Encode a string into bytes by encoding (no BOM)
    fn encode_content(encoding: &str, content: &str) -> Result<Vec<u8>, String> {
        let lower = encoding.to_ascii_lowercase();
        if lower == "utf-16le" || lower == "utf-16be" {
            Ok(Self::encode_utf16(content, lower == "utf-16le"))
        } else if lower == "utf-32le" || lower == "utf-32be" {
            Ok(Self::encode_utf32(content, lower == "utf-32le"))
        } else if lower == "utf-8" {
            Ok(content.as_bytes().to_vec())
        } else {
            Self::encode_string(content, encoding)
        }
    }

    /// Encode FileText back into bytes: restore the BOM as-is
    fn encode_file(ft: &FileText) -> Result<Vec<u8>, String> {
        let mut out: Vec<u8> = ft.bom.to_vec();
        out.extend_from_slice(&Self::encode_content(&ft.encoding, &ft.content)?);
        Ok(out)
    }

    /// Display name of the encoding, with a BOM marker, so the AI can tell
    fn encoding_label(ft: &FileText) -> String {
        if ft.bom.is_empty() {
            ft.encoding.clone()
        } else {
            format!("{}(BOM)", ft.encoding)
        }
    }

    /// Build a line-level unified diff (common prefix/suffix trimmed, only the truly changed parts are shown).
    /// Each side shows at most max_lines; overflow is folded to avoid flooding the output on large changes
    fn unified_diff(old: &str, new: &str, max_lines: usize) -> String {
        if old == new {
            return "  (content unchanged)".to_string();
        }
        let a: Vec<&str> = old.split('\n').collect();
        let b: Vec<&str> = new.split('\n').collect();
        let mut p = 0usize;
        while p < a.len() && p < b.len() && a[p] == b[p] {
            p += 1;
        }
        let mut s = 0usize;
        while s + p < a.len() && s + p < b.len() && a[a.len() - 1 - s] == b[b.len() - 1 - s] {
            s += 1;
        }
        let a_mid = &a[p..a.len() - s];
        let b_mid = &b[p..b.len() - s];
        let mut out = format!(
            "@@ -{},{} +{},{} @@\n",
            p + 1,
            a_mid.len(),
            p + 1,
            b_mid.len()
        );
        for l in a_mid.iter().take(max_lines) {
            out.push_str(&format!("- {}\n", l));
        }
        if a_mid.len() > max_lines {
            out.push_str(&format!("  ... omitted {} deleted lines\n", a_mid.len() - max_lines));
        }
        for l in b_mid.iter().take(max_lines) {
            out.push_str(&format!("+ {}\n", l));
        }
        if b_mid.len() > max_lines {
            out.push_str(&format!("  ... omitted {} added lines\n", b_mid.len() - max_lines));
        }
        out
    }

    /// Dry-run preview for batch section edits: show each matched snippet **independently** as a small labeled hunk,
    /// instead of merging the whole old/new into one "large cross-file" diff from the first to the last change like unified_diff does
    /// (when edits are far apart, all unchanged lines in between get dragged in, raising reading and confirmation cost).
    ///
    /// Each snippet carries only `ctx` lines of context (at most ctx lines before and after), with the landing point labeled by pre-change line number,
    /// and neighboring snippets' contexts are not repeated (planned is sorted by position and non-overlapping).
    /// `content` is the decoded original text (may be \r\n); here it is normalized to LF for display so line numbers align with `line_from/line_to`
    /// (computed against the LF-normalized hay).
    fn sections_diff(content: &str, planned: &[PlannedSection], ctx: usize) -> String {
        if planned.is_empty() {
            return "  (no matched snippet)".to_string();
        }
        let disp = content.replace("\r\n", "\n");
        let lines: Vec<&str> = disp.split('\n').collect();
        let n = lines.len();
        let mut out = String::new();
        // The original line up to which the previous snippet has been output (exclusive), used to avoid a neighboring snippet treating the same line as both "after-context" and "before-context".
        let mut last_ctx_end = 0usize;
        for p in planned {
            let old_from = p.line_from.saturating_sub(1); // 0-based 起始（第 line_from 行）
            let old_to = p.line_to.min(n); // 0-based 结束（不含），第 line_to 行（含）
            if old_from >= old_to {
                // Degenerate case (line range collapsed): still emit the label to avoid missing it
                out.push_str(&format!(
                    "=== edits[{}] line {} (range invalid, check) ===\n",
                    p.idx, p.line_from
                ));
                last_ctx_end = old_to;
                out.push('\n');
                continue;
            }
            // Before-context: do not pass the end already covered by the previous snippet, nor exceed ctx lines
            let gap = old_from.saturating_sub(last_ctx_end);
            let take_before = gap.min(ctx);
            let before_start = old_from.saturating_sub(take_before);
            // After-context
            let after_end = (old_to + ctx).min(n);

            out.push_str(&format!(
                "=== edits[{}] line {}{} ===\n",
                p.idx,
                p.line_from,
                if p.line_from == p.line_to {
                    String::new()
                } else {
                    format!("~{}", p.line_to)
                }
            ));
            for i in before_start..old_from {
                out.push_str(&format!("  {}\n", lines[i]));
            }
            for i in old_from..old_to {
                out.push_str(&format!("- {}\n", lines[i]));
            }
            for nl in p.repl.split('\n') {
                out.push_str(&format!("+ {}\n", nl));
            }
            for i in old_to..after_end {
                out.push_str(&format!("  {}\n", lines[i]));
            }
            last_ctx_end = after_end;
            out.push('\n');
        }
        out
    }

    /// Temp file sequence number, ensuring temp file names are unique under concurrent writes
    fn tmp_seq() -> u64 {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    // ==================== Backup and rollback ====================

    /// Backup root: by default placed under .file-io-mcp-backups/ inside the **directory of the MCP tool itself**,
    /// so it does not pollute the edited project directory. Can be overridden with the FILE_IO_BACKUP_DIR env var
    /// (also useful to point at a writable location when the exe directory is not writable).
    fn backup_root() -> std::path::PathBuf {
        if let Ok(dir) = std::env::var("FILE_IO_BACKUP_DIR") {
            let dir = dir.trim();
            if !dir.is_empty() {
                return std::path::PathBuf::from(dir).join(BACKUP_DIR_NAME);
            }
        }
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(std::env::temp_dir)
            .join(BACKUP_DIR_NAME)
    }

    /// Backup key normalization: must first become a **canonical absolute path** before normalizing, for two reasons:
    /// 1) resolve_path now echoes relative paths; keying directly on a relative path would make the relative/absolute forms of the same file
    ///    land in different backup partitions (manage_backups/undo would then fail to find them);
    /// 2) historical-version keys are "absolute path with \\?\ prefix stripped (lowercased on Windows)", so staying consistent lets old backups keep being found.
    fn backup_path_key(path: &str) -> String {
        let p = std::path::Path::new(path);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            match std::env::current_dir() {
                Ok(cwd) => cwd.join(p),
                Err(_) => p.to_path_buf(),
            }
        };
        let s = Self::resolve_existing_prefix(&abs)
            .to_string_lossy()
            .replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s
        }
    }

    /// Backup directory for a file: <backup root>/<filename>-<absolute-path-hash16>/
    /// Filename + path hash combo is both human-readable and avoids collisions between same-named files in different directories
    fn backup_dir_for(path: &str) -> Option<std::path::PathBuf> {
        let p = std::path::Path::new(path);
        let name = p.file_name()?.to_string_lossy().into_owned();
        // Filename may contain path-illegal characters (very rare); replace them so the directory can be created
        let safe_name: String = name
            .chars()
            .map(|c| if "\\/:*?\"<>|".contains(c) { '_' } else { c })
            .collect();
        let hash = &Self::sha256_hex(Self::backup_path_key(path).as_bytes())[..16];
        Some(Self::backup_root().join(format!("{}-{}", safe_name, hash)))
    }

    /// Pre-write backup: prefer a hard link (**zero-copy when the tool and the edited file are on the same disk**, and a later rename replacement does not affect it,
    /// because atomic write is "write temp file + rename replace", so the old content is still referenced by the hard link);
    /// when the tool and the edited file are on different disks (hard links can't cross volumes, and the backup root is in the tool dir), automatically fall back to copy;
    /// if all fail, return None (does not block the write, only loses rollback ability).
    /// No backup is made if the target file does not exist or exceeds the size limit.
    fn backup_before_write(path: &str, tool: &str, before_bytes: Option<&[u8]>) -> Option<BackupHandle> {
        let meta_src = fs::metadata(path).ok()?;
        if !meta_src.is_file() || meta_src.len() > BACKUP_MAX_FILE_SIZE {
            return None;
        }
        let dir = Self::backup_dir_for(path)?;
        if retry_io(|| fs::create_dir_all(&dir)).is_err() {
            return None;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis();
        // Timestamp + sequence: guarantees backup names are unique under concurrent writes, and lexicographic order equals time order
        let base = format!("{:013}-{:04}", ts, Self::tmp_seq());
        let bak = dir.join(format!("{}.bak", base));
        let mut hardlinked = true;
        if retry_io(|| fs::hard_link(path, &bak)).is_err() {
            hardlinked = false;
            if retry_io(|| fs::copy(path, &bak)).is_err() {
                return None;
            }
        }
        let before_sha = before_bytes
            .map(Self::fingerprint_short_of_bytes)
            .unwrap_or_else(|| {
                Self::fingerprint_short_of_bytes(&fs::read(&bak).unwrap_or_default())
            });
        let meta = dir.join(format!("{}.json", base));
        let info = serde_json::json!({
            "path": path,
            "tool": tool,
            "time_ms": ts,
            "before_sha256": before_sha,
            "after_sha256": serde_json::Value::Null,
            "hardlink": hardlinked,
        });
        let _ = fs::write(&meta, info.to_string());
        // Backup count cap: when exceeded, clean up the oldest ones (along with their meta)
        Self::trim_backups(&dir, BACKUP_KEEP);
        Some(BackupHandle { bak, meta })
    }

    /// 写入完成后补齐"写入后 sha256"，供回滚时判断文件是否又被改过
    fn finish_backup(handle: &BackupHandle, after_bytes: &[u8]) {
        let Ok(text) = fs::read_to_string(&handle.meta) else {
            return;
        };
        let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return;
        };
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "after_sha256".to_string(),
                // Same convention as the sha256 returned by read tools, for direct comparison
                serde_json::Value::String(Self::fingerprint_short_of_bytes(after_bytes)),
            );
        }
        let _ = fs::write(&handle.meta, v.to_string());
    }

    /// Convert a hard-link backup into an independent copy (called before in-place overwrite), so the backup content is not rewritten together
    fn materialize_hardlink_backup(bak: &std::path::Path) {
        let Ok(data) = fs::read(bak) else {
            return;
        };
        let tmp = bak.with_extension("mat");
        if fs::write(&tmp, &data).is_ok() {
            let _ = fs::rename(&tmp, bak);
        }
    }

    /// Trim the backup directory: keep only the newest `keep` copies (sorted by filename, timestamp first); remove the extras along with their meta;
    /// delete the directory too once emptied, to avoid leaving a pile of empty directories
    fn trim_backups(dir: &std::path::Path, keep: usize) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut baks: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "bak").unwrap_or(false))
            .collect();
        baks.sort();
        if baks.len() > keep {
            let remove_count = baks.len() - keep;
            for old in baks.iter().take(remove_count) {
                let _ = retry_io(|| fs::remove_file(old));
                let _ = fs::remove_file(old.with_extension("json"));
            }
        }
        // Delete the directory once empty (including leftover .mat temp files)
        if let Ok(rest) = fs::read_dir(dir) {
            if rest.filter_map(|e| e.ok()).count() == 0 {
                let _ = fs::remove_dir(dir);
            }
        }
    }

    /// List a file's backups (ascending by time)
    fn list_backup_records(path: &str) -> Vec<(std::path::PathBuf, serde_json::Value)> {
        let Some(dir) = Self::backup_dir_for(path) else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut baks: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "bak").unwrap_or(false))
            .collect();
        baks.sort();
        baks.into_iter()
            .filter_map(|bak| {
                let meta = bak.with_extension("json");
                let v = fs::read_to_string(&meta)
                    .ok()
                    .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())?;
                // Guard against hash collisions in extreme cases: the original path recorded in meta must match this file
                let recorded = v.get("path").and_then(|x| x.as_str())?;
                if !Self::same_path(recorded, path) {
                    return None;
                }
                Some((bak, v))
            })
            .collect()
    }

    /// Path equivalence check (borrows the backup key's normalization rules: separators, \\?\ prefix, Windows case sensitivity)
    fn same_path(a: &str, b: &str) -> bool {
        Self::backup_path_key(a) == Self::backup_path_key(b)
    }


    /// Atomic write: first write a same-directory temp file and flush it to disk, then atomically replace the target with rename.
    /// Benefit: at any moment you read either the complete old file or the complete new file, never half-written content.
    /// On rename failure (e.g. target held by IDE/antivirus), fall back to in-place overwrite,
    /// so scenarios that could originally be written still can be, instead of failing due to atomization.
    ///
    /// active_backup: the backup file for this write. The backup may be a hard link (sharing the inode with the target),
    /// so the in-place-overwrite fallback would pollute the backup too; therefore convert the hard link to an independent copy before falling back.
    fn atomic_write_ex(
        path: &str,
        bytes: &[u8],
        active_backup: Option<&std::path::Path>,
    ) -> std::io::Result<()> {
        let p = std::path::Path::new(path);
        let dir = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let file_name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let tmp = dir.join(format!(
            ".{}.file-io-mcp-{}-{}.tmp",
            file_name,
            std::process::id(),
            Self::tmp_seq()
        ));

        // 1) Write the temp file and force it to disk
        if let Err(e) = retry_io(|| -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.flush()?;
            f.sync_all()?;
            Ok(())
        }) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        // 2) Atomic replace
        match retry_io(|| fs::rename(&tmp, p)) {
            Ok(()) => Ok(()),
            Err(_rename_err) => {
                let _ = fs::remove_file(&tmp);
                // 3) Fallback: in-place overwrite (non-atomic, but guarantees writability)
                //    In-place write changes the inode content; if the backup is a hard link it would be rewritten too, so convert it to an independent copy first
                if let Some(bak) = active_backup {
                    Self::materialize_hardlink_backup(bak);
                }
                retry_io(|| fs::write(p, bytes))
            }
        }
    }

    /// Pre-write guard for write operations: prevents the AI from writing by mistake without confirming the current content.
    /// expected_old matches, per mode, the content of the "range you intend to change":
    /// - overwrite: the whole file
    /// - append: the file tail (append point)
    /// - insert: around the insert offset
    /// On mismatch, refuse the write and return the current content of that range.
    fn check_write_guard(
        path: &str,
        encoding_name: &str,
        mode: &str,
        offset: Option<u64>,
        expected_old: Option<&str>,
        existing: Option<&[u8]>,
    ) -> Result<(), McpError> {
        let Some(exp) = expected_old else {
            return Ok(());
        };
        // Reuse the bytes the caller already read, to avoid reading the same file from disk twice; only fall back to disk when not provided
        let owned;
        let bytes: &[u8] = match existing {
            Some(b) => b,
            None => {
                if !std::path::Path::new(path).exists() {
                    return Err(e_param(
                        format!(
                            "file does not exist: {}. expected_old was provided, implying the file should exist; please check the path",
                            path
                        ),
                        None,
                    ));
                }
                owned = fs::read(path)
                    .map_err(|e| e_internal(format!("failed to read file: {}", e), None))?;
                &owned
            }
        };

        // Single decode entry (strips BOM), ensuring consistency with the content convention used at write time
        let actual_content = Self::decode_file(bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?
            .content;

        // CRLF normalization: read_text_lines already strips trailing \r on read, so normalize before comparing to avoid false rejection.
        // Use Cow: most content contains no \r, so zero allocation here (the old impl copied the whole string on every comparison)
        fn norm(s: &str) -> std::borrow::Cow<'_, str> {
            if s.contains('\r') {
                std::borrow::Cow::Owned(s.replace("\r\n", "\n"))
            } else {
                std::borrow::Cow::Borrowed(s)
            }
        }

        // Determine the "range you intend to change" by mode and compare
        let (matched, scope, shown): (bool, String, String) = match mode {
            "append" => {
                // Match the file tail content (append point)
                let tail: String = actual_content
                    .chars()
                    .rev()
                    .take(exp.chars().count())
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect();
                let shown: String = actual_content
                    .chars()
                    .rev()
                    .take(1000)
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect();
                (norm(&tail) == norm(exp), "end of file (append point)".to_string(), shown)
            }
            "insert" => {
                // offset is the **raw byte offset including the BOM**, on the same basis as the write path;
                // the window must be taken directly on the raw bytes -- using the decoded String's UTF-8 indices would be off
                // for files with a BOM (off by 3 bytes overall) and for GBK/UTF-16 (completely different index space).
                let off = offset.unwrap_or(0) as usize;
                let bom_len = Self::detect_bom(bytes).len();
                if off < bom_len {
                    return Err(e_param(
                        format!(
                            "insert point offset={} falls inside the file BOM (BOM is {} bytes; inserting would break encoding). Use offset>={} instead",
                            off, bom_len, bom_len
                        ),
                        None,
                    ));
                }
                let off_c = off.min(bytes.len());
                if !Self::is_char_boundary(encoding_name, bytes, off_c) {
                    return Err(e_param(
                        format!(
                            "insert point offset={} is not on a character boundary of {} (would split a multi-byte character)",
                            off, encoding_name
                        ),
                        None,
                    ));
                }
                let tail_text = Self::decode_file(&bytes[off_c..], encoding_name)
                    .map_err(|e| e_internal(e, None))?
                    .content;
                let window: String = tail_text.chars().take(exp.chars().count()).collect();
                let shown: String = tail_text.chars().take(800).collect();
                (norm(&window) == norm(exp), format!("insert point offset={}", off), shown)
            }
            _ => {
                // For large files only echo a head/tail digest, to avoid echoing the whole file (possibly sensitive) content
                (
                    norm(&actual_content) == norm(exp),
                    "entire file".to_string(),
                    Self::clip_guard_preview(&actual_content),
                )
            }
        };

        if matched {
            return Ok(());
        }
        Err(e_param(
            format!(
                "expected_old mismatch, write rejected! The file may have been modified or you did not read it fully.\n=== actual content of the range you intended to change [{}]:\n{}",
                scope, shown
            ),
            None,
        ))
    }

    /// The "current content" preview echoed when the guard check fails:
    /// returns as-is when short; when too long, keeps only head/tail plus length and fingerprint, to avoid echoing the whole file (large-file flood / sensitive-content leak)
    fn clip_guard_preview(content: &str) -> String {
        const PREVIEW_HEAD: usize = 2000;
        const PREVIEW_TAIL: usize = 500;
        let chars: Vec<char> = content.chars().collect();
        if chars.len() <= PREVIEW_HEAD + PREVIEW_TAIL {
            return content.to_string();
        }
        let head: String = chars[..PREVIEW_HEAD].iter().collect();
        let tail: String = chars[chars.len() - PREVIEW_TAIL..].iter().collect();
        format!(
            "{}\n... ({} characters omitted in the middle; {} total characters; content fingerprint (NOT the file sha256, do not use as expected_sha256):{})...\n{}",
            head,
            chars.len() - PREVIEW_HEAD - PREVIEW_TAIL,
            chars.len(),
            Self::fingerprint_short_of_bytes(content.as_bytes()),
            tail
        )
    }

    /// Encoding decision for write operations:
    /// - file exists: detect the actual encoding; when unspecified or auto, write back in the original encoding;
    ///   when an explicit encoding conflicts with the actual one, error out and return the file's real encoding (preventing the encoding from being silently corrupted).
    /// - file does not exist (new): use the specified encoding (default utf-8).
    fn resolve_write_encoding(
        path: &str,
        requested: Option<&str>,
        existing_bytes: Option<&[u8]>,
    ) -> Result<&'static str, McpError> {
        let actual = existing_bytes.map(Self::detect_encoding);
        let req = match requested {
            Some(name) if Self::encoding_is_auto(Some(name)) => None,
            Some(name) => Some(name),
            None => None,
        };
        match (req, actual) {
            (None, Some(act)) => Ok(act),
            (None, None) => Ok("utf-8"),
            (Some(r), None) => Self::canonical_encoding(r).map_err(|e| e_param(e, None)),
            (Some(r), Some(act)) => {
                let rn = Self::canonical_encoding(r).map_err(|e| e_param(e, None))?;
                if rn.eq_ignore_ascii_case(act) {
                    return Ok(rn);
                }
                Err(e_param(
                    format!(
                        "encoding mismatch, write refused! The actual encoding of file {} is [{}], but you specified [{}]. Writing directly would corrupt the encoding.\n\
                         Use encoding='{}' to keep the original encoding and retry",
                        path, act, rn, act
                    ),
                    None,
                ))
            }
        }
    }

    /// Recursively collect file paths to search under a directory
    /// - include: a file is collected only when any glob matches (matched against both filename and relative root path)
    /// - exclude: a file is skipped when any glob matches; matching a directory prunes the whole subtree
    /// - stat: records filtering/pruning/truncation, so output can explain to the caller "what was found and why not everything was searched"
    fn collect_files(
        dir: &std::path::Path,
        root: &std::path::Path,
        ext_filter: &[String],
        include: &Option<Vec<GlobMatcher>>,
        exclude: &Option<Vec<GlobMatcher>>,
        recursive: bool,
        skip_hidden: bool,
        default_skip: bool,
        max_files: usize,
        files: &mut Vec<String>,
        stat: &mut SearchScanStat,
    ) -> Result<(), String> {
        let entries = fs::read_dir(dir)
            .map_err(|e| format!("cannot read directory {}: {}", dir.display(), e))?;

        let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        sorted.sort_by_cached_key(|e| e.file_name());

        for entry in sorted {
            if files.len() >= max_files {
                stat.capped = true;
                return Ok(());
            }

            // Skip backup dirs / temp files / lock files produced by this tool itself
            let name = entry.file_name().to_string_lossy().to_string();
            if is_internal_file(&name) {
                continue;
            }

            let entry_path = entry.path();
            // Path relative to the search root (unified with / separator), for matching globs like "src/**/*.rs"
            let rel = entry_path
                .strip_prefix(root)
                .unwrap_or(entry_path.as_path())
                .to_string_lossy()
                .replace('\\', "/");

            let file_type = entry.file_type().ok();
            let is_dir = file_type.as_ref().map(|ft| ft.is_dir()).unwrap_or(false);
            let is_file = file_type.as_ref().map(|ft| ft.is_file()).unwrap_or(false);

            // Hidden items (starting with ., e.g. .git/.env) are skipped by default; explicitly named by include are allowed
            let hidden = skip_hidden
                && name.starts_with('.')
                && !Self::glob_match_any(&name, &rel, include);

            if is_dir {
                // When exclude matches a directory, prune the whole subtree and do not recurse in (e.g. "node_modules/**")
                if Self::dir_excluded(&name, &rel, exclude) {
                    stat.pruned_dirs += 1;
                    continue;
                }
                if hidden {
                    stat.pruned_dirs += 1;
                    continue;
                }
                if recursive {
                    Self::collect_files(
                        &entry_path, root, ext_filter, include, exclude, recursive, skip_hidden,
                        default_skip, max_files, files, stat,
                    )?;
                }
                continue;
            }

            if is_file {
                if hidden {
                    stat.filtered += 1;
                    continue;
                }
                if Self::glob_match_any(&name, &rel, exclude) {
                    stat.filtered += 1;
                    continue;
                }
                if include.is_some() && !Self::glob_match_any(&name, &rel, include) {
                    stat.filtered += 1;
                    continue;
                }
                // When extension/extensions/include are not specified, skip binaries/build artifacts by default,
                // so the budget focuses on source text (specifying any of them fully respects the user's choice and skips nothing extra)
                if default_skip {
                    let ext = entry_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.to_lowercase())
                        .unwrap_or_default();
                    if DEFAULT_SKIP_EXTS.contains(&ext.as_str()) {
                        stat.default_filtered += 1;
                        continue;
                    }
                }
                if !ext_filter.is_empty() {
                    let file_ext = entry_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.to_lowercase())
                        .unwrap_or_default();
                    if !ext_filter.contains(&file_ext) {
                        stat.filtered += 1;
                        continue;
                    }
                }
                files.push(entry_path.to_string_lossy().to_string());
            }
        }
        Ok(())
    }

    /// Glob match test: matches against both filename and relative path
    /// ("*.rs" matches the filename, "src/**/*.rs" matches the relative path)
    fn glob_match_any(name: &str, rel: &str, matchers: &Option<Vec<GlobMatcher>>) -> bool {
        match matchers {
            None => false,
            Some(ms) => ms.iter().any(|m| m.is_match(name) || m.is_match(rel)),
        }
    }

    /// Whether a directory is hit by exclude: additionally tries "{rel}/child" once more,
    /// so patterns like "node_modules/**", "**/dist/**" can also prune the directory itself
    fn dir_excluded(name: &str, rel: &str, exclude: &Option<Vec<GlobMatcher>>) -> bool {
        if Self::glob_match_any(name, rel, exclude) {
            return true;
        }
        match exclude {
            None => false,
            Some(ms) => {
                let child = format!("{}/__x__", rel);
                ms.iter().any(|m| m.is_match(&child))
            }
        }
    }

    /// Compile a glob list; an empty list is treated as unset
    fn compile_globs(
        list: &Option<Vec<String>>,
        field: &str,
    ) -> Result<Option<Vec<GlobMatcher>>, McpError> {
        match list {
            None => Ok(None),
            Some(items) => {
                if items.is_empty() {
                    return Ok(None);
                }
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    let g = Glob::new(it).map_err(|e| {
                        e_param(format!("glob expression '{}' for {} is invalid: {}", field, it, e), None)
                    })?;
                    out.push(g.compile_matcher());
                }
                Ok(Some(out))
            }
        }
    }

    /// Read a file to search and decode it, returning (effective encoding name, content, raw bytes); on failure give a readable reason (no more silent skips).
    /// The fingerprint is computed by the caller only when there is an actual hit, to avoid a full hash for candidate files that don't match.
    fn read_search_content(
        file_path: &str,
        encoding_raw: Option<&str>,
        encoding_auto: bool,
    ) -> Result<(String, String, Vec<u8>), String> {
        // Check size before reading: oversized files need not be read fully into memory (message consistent with before)
        let size = fs::metadata(file_path)
            .map_err(|e| format!("read failed: {}", e))?
            .len();
        if size > MAX_REGEX_FILE_SIZE {
            return Err(format!(
                "file too large ({}B > {}B), skipped",
                size, MAX_REGEX_FILE_SIZE
            ));
        }
        let bytes = fs::read(file_path).map_err(|e| format!("read failed: {}", e))?;
        if encoding_auto {
            let detected = Self::detect_encoding(&bytes);
            // If the auto-detected encoding still has invalid bytes, fall back to lenient decoding (U+FFFD replacement) instead of skipping the whole file,
            // to avoid missing files in a directory search; an explicitly specified encoding still errors strictly.
            // Always go through decode_file: UTF-16/UTF-32 are handled by the built-in impl (encoding_rs does not support UTF-32),
            // and it also strips the BOM, avoiding BOM characters leaking into search results.
            let content = match Self::decode_file(&bytes, detected) {
                Ok(ft) => ft.content,
                // Lenient fallback: when the encoding is not in encoding_rs or contains invalid bytes, use replacement decoding to avoid skipping the whole file
                Err(_) => match Self::get_encoding(detected) {
                    Ok(enc) => enc.decode(&bytes).0.into_owned(),
                    Err(_) => String::from_utf8_lossy(&bytes).into_owned(),
                },
            };
            Ok((detected.to_string(), content, bytes))
        } else {
            let name = encoding_raw.unwrap_or("utf-8");
            if name.eq_ignore_ascii_case("utf-8") {
                match std::str::from_utf8(&bytes) {
                    Ok(s) => Ok(("utf-8".to_string(), s.to_string(), bytes)),
                    Err(_) => Err(
                        "not valid UTF-8 text (you may specify encoding=\"auto\" or an explicit encoding such as gbk)"
                            .to_string(),
                    ),
                }
            } else {
                // Also go through decode_file: explicitly specifying utf-16/utf-32 is searchable too
                let content = Self::decode_file(&bytes, name)
                    .map_err(|e| format!("failed to decode with {} ({})", name, e))?
                    .content;
                Ok((name.to_string(), content, bytes))
            }
        }
    }

    /// Single-line text shown in search results: truncate when too long, to avoid one line flooding the output (keeps original indentation, usable directly as expected_old)
    fn clip_line(line: &str) -> String {
        const MAX_SEARCH_LINE_LEN: usize = 300;
        let chars: Vec<char> = line.chars().collect();
        if chars.len() <= MAX_SEARCH_LINE_LEN {
            line.to_string()
        } else {
            let head: String = chars[..MAX_SEARCH_LINE_LEN].iter().collect();
            format!("{}... (this line has {} characters total, truncated)", head, chars.len())
        }
    }
}

#[tool_router]
impl FileIoServer {
    /// 读取文本文件
    #[tool(
        name = "read_text_file",
        description = "Read a text fragment by byte offset/length (offset/length >= 1, default up to 10MB). Returns a header: path | encoding (BOM) | size | sha256 | range; the range is auto-snapped to character boundaries by default (flagged), use strict=true for exact byte ranges. For line-based editing use read_text_lines",
        annotations(title = "Read text file", read_only_hint = true)
    )]
    fn read_text_file(
        &self,
        Parameters(params): Parameters<ReadTextFileParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let show_ln = params.show_line_numbers.unwrap_or(false);
        let mut file = File::open(&params.path)
            .map_err(|e| e_internal(format!("failed to open file: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| e_internal(format!("failed to get file metadata: {}", e), None))?
            .len();

        let mut start = params.offset.unwrap_or(0);

        // length=0 has no "sensible meaning" (neither reading empty nor reading all), so reject explicitly rather than leaving it to interpretation
        if params.length == Some(0) {
            return Err(e_param(
                "length must be >=1. For size/fingerprint only use file_info; to read everything omit length",
                None,
            ));
        }
        // strict=true: length/offset take effect exactly (no "read at least 4 bytes", no flooring of offset),
        // use it when you need exact paging/byte alignment; otherwise length is only a hint and the actual range may be adjusted (the header will note it).
        let strict = params.strict.unwrap_or(false);

        // Allow offset=0 to read an empty file (returns empty content); only error when the offset passes the end of file
        if start > 0 && start >= file_size {
            return Err(e_param(
                format!("offset={} is out of file range (file is {}B total)", start, file_size),
                None,
            ));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("seek failed: {}", e), None))?;

        // Hard cap: no matter how large length is, never read more than MAX_READ_HARD_LIMIT at once, to avoid memory/response blowups
        let max_len = params
            .length
            .unwrap_or(MAX_TEXT_READ_SIZE)
            .min(MAX_READ_HARD_LIMIT);
        let room = (file_size - start) as usize;
        // When not strict, length is a hint: read at least 4 bytes so the window covers a complete multi-byte character,
        // otherwise paging would stall when length is too small; in strict mode read exactly length.
        let mut read_len = if strict {
            max_len.min(room)
        } else {
            max_len.min(room).max(room.min(4))
        };
        // Already at EOF (room=0) does not count as "truncated", otherwise a false truncation warning would fire
        let mut truncated = read_len < room && read_len > 0;
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| e_internal(format!("read failed: {}", e), None))?;

        // Encoding decision: use an explicit value directly; on auto/unspecified, always detect from the **whole file**,
        // never from this read window -- the window may start/end inside a multi-byte character, making UTF-8 validation fail and misjudge it as GBK.
        let requested_enc = params.encoding.as_deref();
        let auto_detect = Self::encoding_is_auto(requested_enc);
        let (encoding_name, enc_confident) = if auto_detect {
            let probe = Self::encoding_probe_bytes(&params.path, start, truncated, &buffer)
                .map_err(|e| e_internal(e, None))?;
            Self::detect_encoding_with_confidence(&probe)
        } else {
            // Go through canonical_encoding: UTF-32 is not in encoding_rs, but an explicit value must still pass
            (
                Self::canonical_encoding(requested_enc.unwrap_or("utf-8"))
                    .map_err(|e| e_param(e, None))?,
                true,
            )
        };
        // offset may land inside a multi-byte character (almost always when paging by read_len). Floor it to a character boundary,
        // otherwise decoding from "half a character" yields an invalid-byte error, making paged reads of UTF-8 files fail from the second page on.
        // In strict mode this fallback is skipped (the caller wants an exact range), and the later "drop incomplete edge bytes" handles it.
        let aligned = if strict {
            start
        } else {
            Self::floor_char_boundary(encoding_name, &params.path, start, buffer.first().copied())
        };
        let align_note = if aligned != start {
            start = aligned;
            file.seek(SeekFrom::Start(start))
                .map_err(|e| e_internal(format!("seek failed: {}", e), None))?;
            let remaining = (file_size - start) as usize;
            read_len = if strict {
                max_len.min(remaining)
            } else {
                max_len.min(remaining).max(remaining.min(4))
            };
            truncated = read_len < remaining && read_len > 0;
            buffer = vec![0u8; read_len];
            file.read_exact(&mut buffer)
                .map_err(|e| e_internal(format!("read failed: {}", e), None))?;
            format!(" ⚠️offset snapped down to character boundary: {}", start)
        } else {
            String::new()
        };

        // Count prefix line numbers after boundary alignment, so the displayed line numbers match the final start
        let prefix_line_count = if show_ln && start > 0 {
            Self::count_newlines_before(&mut file, start)
                .map_err(|e| e_internal(format!("failed to read prefix: {}", e), None))?
        } else {
            0
        };

        // When reading from offset=0, the head may carry a BOM, which must be stripped and the AI-visible encoding name returned
        let bom = if start == 0 { Self::detect_bom(&buffer) } else { &[][..] };
        // In strict mode the window start may land exactly inside a character: drop the incomplete bytes at the start
        // (UTF-8 continuation bytes look like 10xxxxxx, at most 3; other encodings can't be checked cheaply and will error on decode failure)
        let mut lead_skip = 0usize;
        if strict && encoding_name.eq_ignore_ascii_case("utf-8") {
            while lead_skip < buffer.len().min(3) && (buffer[lead_skip] & 0xC0) == 0x80 {
                lead_skip += 1;
            }
        }
        let body = &buffer[bom.len() + lead_skip..];
        let encoding_label = if bom.is_empty() {
            encoding_name.to_string()
        } else {
            format!("{}(BOM)", encoding_name)
        };
        let enc_warn = if enc_confident {
            String::new()
        } else {
            " ⚠️encoding uncertain (GBK/UTF-8 ambiguous); specify encoding explicitly and re-read".to_string()
        };

        // Only decode this read window. The window is truncated by bytes, and the tail may be "half a multi-byte character",
        // which is normal truncation, not file corruption: tolerate an incomplete trailing sequence on truncation, to avoid failing the whole read.
        // consumed records the bytes in the window that "truly form complete characters", used to also align the right end of the returned range to a character boundary.
        // Strict mode must also tolerate edges (it may itself cut inside a character); edge_note reports it separately.
        let tolerate_edges = truncated || strict;
        let mut consumed = body.len();
        let content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            match std::str::from_utf8(body) {
                Ok(s) => s.to_string(),
                Err(e) if tolerate_edges && e.error_len().is_none() => {
                    consumed = e.valid_up_to();
                    std::str::from_utf8(&body[..consumed])
                        .unwrap_or("")
                        .to_string()
                }
                Err(_) => {
                    return Err(e_internal(
                        format!(
                            "file is not valid UTF-8 (the {} bytes read from offset {} contain invalid bytes); try specifying the correct encoding parameter",
                            start,
                            body.len()
                        ),
                        None,
                    ));
                }
            }
        } else if encoding_name.eq_ignore_ascii_case("utf-32le")
            || encoding_name.eq_ignore_ascii_case("utf-32be")
        {
            // encoding_rs does not support UTF-32: align to 4 bytes, drop the incomplete trailing code unit, then use the built-in decode
            let mut end = body.len();
            if tolerate_edges {
                end -= end % 4;
            }
            consumed = end;
            Self::decode_utf32(&body[..end], encoding_name.eq_ignore_ascii_case("utf-32le"))
                .map_err(|e| e_internal(e, None))?
        } else if tolerate_edges {
            // Same for double/multi-byte encodings: the tail may be truncated inside a character; step back byte by byte (up to 4) and retry
            let mut end = body.len();
            let mut decoded: Option<String> = None;
            loop {
                match Self::decode_bytes(&body[..end], encoding_name) {
                    Ok(s) => {
                        decoded = Some(s);
                        consumed = end;
                        break;
                    }
                    Err(_) => {
                        if end == 0 || body.len() - end >= 4 {
                            break;
                        }
                        end -= 1;
                    }
                }
            }
            match decoded {
                Some(s) => s,
                None => {
                    return Err(e_internal(
                        format!(
                            "decode with {} failed (the window from offset {} contains invalid bytes).\
                             If this is from byte-precise paging with strict=true that cut inside a character, dropping strict auto-aligns to the character boundary",
                            encoding_name, start
                        ),
                        None,
                    ));
                }
            }
        } else {
            Self::decode_bytes(body, encoding_name)
                .map_err(|e| e_internal(e, None))?
        };
        // Right end of the returned range: start + BOM + bytes actually consumed as complete characters (guaranteed on a character boundary)
        let end_off = start + bom.len() as u64 + consumed as u64;

        // Clearly report when strict mode dropped incomplete edge bytes (non-strict's tail tolerance is already reflected in the right end / truncation warning)
        let edge_note = if strict && (lead_skip > 0 || consumed < body.len()) {
            format!(
                " ⚠️strict: dropped {}B of incomplete edge bytes to land on a character boundary (actually returned [{},{}); omit strict to remove this behavior)",
                lead_skip + (body.len() - consumed),
                start,
                end_off
            )
        } else {
            String::new()
        };

        let display_content = if show_ln {
            // Starting line number: prefix newline count + 1 (1-based)
            let start_line = prefix_line_count + 1;
            let width = (start_line + content.lines().count()).to_string().len().max(3);
            content
                .lines()
                .enumerate()
                .map(|(i, line)| format!("{:>width$}| {}", start_line + i, line, width = width))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            content
        };

        let trunc_warn = if truncated {
            format!(
                " ⚠️truncated: file is {}B total, only [{},{}) returned. For full editing use read_text_lines, or page the rest with offset",
                file_size, start, end_off
            )
        } else {
            String::new()
        };

        // Version fingerprint (returned as expected_sha256 on later writes, to prevent concurrent changes from being overwritten).
        // Large files use a sampled fingerprint, to avoid "reading only a small segment but hashing the whole large file again".
        // The criterion must be "buffer truly covers the whole file", not !truncated: when length=0, truncated is false
        // but buffer is empty, which would hash an empty string as the file fingerprint (the AI's echo-back would surely trigger a false E_EXTERNAL_CHANGED).
        // Note: must use the full buffer (including BOM), not the BOM-stripped body, otherwise the fingerprint won't match the actual file.
        let sha = if start == 0 && buffer.len() as u64 == file_size {
            Self::fingerprint_short_of_bytes(&buffer)
        } else {
            Self::path_fingerprint_short(&params.path)
        };

        Ok(format!(
            "{}{}{}{}{} | {} | {}B | sha256:{} | [{},{}){}```\n{}\n```",
            params.path,
            trunc_warn,
            align_note,
            edge_note,
            enc_warn,
            encoding_label,
            file_size,
            sha,
            start,
            end_off,
            if show_ln { " | lines" } else { "" },
            display_content
        ))
    }

    /// 写入文本文件
    #[tool(
        name = "write_text_file",
        description = "Write text in one shot (auto-creates directories). mode=overwrite (default)/append/insert (needs offset, must land on a character boundary). Pass expected_old for a pre-write check; dry_run=true returns only a diff",
        annotations(title = "Write text file", destructive_hint = true)
    )]
    fn write_text_file(
        &self,
        Parameters(params): Parameters<WriteTextFileParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let mode = params.mode.as_deref().unwrap_or("overwrite");
        // Validate the mode first, so an unknown mode doesn't run side effects like dir creation / pre-write checks
        if !matches!(mode, "overwrite" | "append" | "insert") {
            return Err(e_param(
                format!("unsupported mode: {}, choose from: overwrite, append, insert", mode),
                None,
            ));
        }

        // Serialize read-modify-write for the same file: multiple AIs writing the same file concurrently won't overwrite each other
        self.with_path_lock(&params.path, || {
        // If the file exists, read the original bytes for encoding detection (keep the original encoding on write)
        let existing_bytes: Option<Vec<u8>> = if std::path::Path::new(&params.path).exists() {
            Some(fs::read(&params.path).map_err(|e| {
                e_internal(format!("failed to read the original file: {}", e), None)
            })?)
        } else {
            None
        };

        // Pre-write version check: refuse if the file was changed by another AI/program, to avoid wiping others' changes
        Self::check_expected_sha(
            &params.path,
            existing_bytes.as_deref().unwrap_or(&[]),
            params.expected_sha256.as_deref(),
        )?;

        // Decide the write encoding: keep the original file encoding when unspecified/auto; when the specified encoding conflicts with the actual one, error and return the real encoding
        let encoding_name = Self::resolve_write_encoding(
            &params.path,
            params.encoding.as_deref(),
            existing_bytes.as_deref(),
        )?;

        // Encoding self-consistency check (only on the auto-detect path): if the detected encoding cannot losslessly decode the existing file,
        // the detection is unreliable (typical: a GBK file misjudged as UTF-8), and continuing to write may corrupt the file into mojibake, so refuse.
        // An explicit encoding is guaranteed consistent with the original file by resolve_write_encoding, so no re-check needed.
        // (Shares the same implementation with edit_file_sections to avoid logic drift between the two places)
        if Self::encoding_is_auto(params.encoding.as_deref()) {
            if let Some(b) = existing_bytes.as_deref() {
                Self::check_encoding_lossless(encoding_name, b)?;
            }
        }

        // Convert content to bytes in the specified encoding (no BOM; BOM is added at the file head only on overwrite)
        let bytes: Vec<u8> = Self::encode_content(encoding_name, &params.content)
            .map_err(|e| e_internal(e, None))?;

        // Auto-create the parent directory
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| e_internal(e, None))?;

        // Pre-write guard (checks "the range you intend to change" by mode): prevents writing by mistake without confirming current content;
        // reuses the existing_bytes already read above, to avoid reading the same file from disk twice
        Self::check_write_guard(
            &params.path,
            encoding_name,
            mode,
            params.offset,
            params.expected_old.as_deref(),
            existing_bytes.as_deref(),
        )?;

        // BOM handling:
        // - file exists: restore the original BOM as-is, otherwise encoding info is lost (UTF-16 would degrade into GBK mojibake)
        // - new file: UTF-16/32 must carry their own BOM, otherwise it can't be recognized next time and would be misjudged as GBK
        let bom: &[u8] = match existing_bytes.as_deref() {
            Some(b) => Self::detect_bom(b),
            None => Self::default_bom_for(encoding_name),
        };
        let encoding_label = if bom.is_empty() {
            encoding_name.to_string()
        } else {
            format!("{}(BOM)", encoding_name)
        };

        // dry-run: only return a diff preview, don't write the file or back it up
        if params.dry_run.unwrap_or(false) {
            let old_text = match existing_bytes.as_deref() {
                Some(b) => Self::decode_file(b, encoding_name)
                    .map_err(|e| e_internal(e, None))?
                    .content,
                None => String::new(),
            };
            let new_full: Vec<u8> = match mode {
                "overwrite" => {
                    let mut v = bom.to_vec();
                    v.extend_from_slice(&bytes);
                    v
                }
                "append" => {
                    // Consistent with the real write: a new file must prepend the default BOM, otherwise the preview's predicted sha won't match what's written
                    let mut v = if existing_bytes.is_none() {
                        bom.to_vec()
                    } else {
                        Vec::new()
                    };
                    if let Some(b) = existing_bytes.as_deref() {
                        v.extend_from_slice(b);
                    }
                    v.extend_from_slice(&bytes);
                    v
                }
                "insert" => {
                    let original = existing_bytes.clone().ok_or_else(|| {
                        e_param(
                            format!(
                                "insert mode requires the file to exist, but it does not: {}. Use overwrite mode to create a new file",
                                params.path
                            ),
                            None,
                        )
                    })?;
                    let off = (params.offset.unwrap_or(0) as usize).min(original.len());
                    if off < bom.len() {
                        return Err(e_param(
                            format!(
                                "insert offset={} falls inside the file BOM (BOM is {} bytes; inserting would break encoding). Use offset>={} or overwrite mode",
                                off,
                                bom.len(),
                                bom.len()
                            ),
                            None,
                        ));
                    }
                    let mut v = Vec::with_capacity(original.len() + bytes.len());
                    v.extend_from_slice(&original[..off]);
                    v.extend_from_slice(&bytes);
                    v.extend_from_slice(&original[off..]);
                    v
                }
                _ => Vec::new(),
            };
            let new_text = Self::decode_file(&new_full, encoding_name)
                .map_err(|e| e_internal(e, None))?
                .content;
            return Ok(format!(
                "DRY-RUN | {} | {} | mode={} | {}B→{}B | not written\n{}expected sha256:{}\nremove dry_run and retry to write",
                params.path,
                encoding_label,
                mode,
                old_text.len(),
                new_text.len(),
                Self::unified_diff(&old_text, &new_text, 200),
                Self::fingerprint_short_of_bytes(&new_full)
            ));
        }

        match mode {
            "overwrite" => {
                let mut out: Vec<u8> = bom.to_vec();
                out.extend_from_slice(&bytes);
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_text_file:overwrite",
                    existing_bytes.as_deref(),
                );
                Self::atomic_write_ex(&params.path, &out, bak.as_ref().map(|b| b.bak.as_path()))
                    .map_err(|e| e_internal(format!("E_WRITE write failed: {}", e), None))?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &out);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {} | {}B | sha256:{}{}", params.path, encoding_label, out.len(), Self::fingerprint_short_of_bytes(&out), tail))
            }
            "append" => {
                // append is "in-place append", and a hard-link backup would change with it, so no backup is made (rollback is covered by OCC + atomic write for the other modes).
                // For a new file (existing is empty) the default BOM must be prepended first, otherwise UTF-16/32 would be written "BOM-less" and misjudged as GBK next time.
                let prefix: &[u8] = if existing_bytes.is_none() { bom } else { &[] };
                retry_io(|| {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&params.path)?;
                    if !prefix.is_empty() {
                        file.write_all(prefix)?;
                    }
                    file.write_all(&bytes)?;
                    file.flush()?;
                    Ok(())
                })
                .map_err(|e| e_internal(format!("E_WRITE append failed: {}", e), None))?;
                let mut full = existing_bytes.clone().unwrap_or_default();
                full.extend_from_slice(prefix);
                full.extend_from_slice(&bytes);
                let added = prefix.len() + bytes.len();
                Ok(format!("OK {} | {} | +{}B append | sha256:{}", params.path, encoding_label, added, Self::fingerprint_short_of_bytes(&full)))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                let original = existing_bytes.clone().ok_or_else(|| {
                    e_param(
                        format!("insert mode requires the file to exist, but it does not: {}. Use overwrite mode to create a new file", params.path),
                        None,
                    )
                })?;
                let off = off.min(original.len());
                // offset is the raw byte offset including the BOM: landing inside the BOM would insert the new content before/in the middle of the BOM, directly breaking the encoding
                if off < bom.len() {
                    return Err(e_param(
                        format!(
                            "insert 的 offset={} 落在文件 BOM 内（BOM 占 {} 字节，插入会破坏编码）。请改用 offset>={} 或 overwrite 模式",
                            off,
                            bom.len(),
                            bom.len()
                        ),
                        None,
                    ));
                }
                // offset is a byte offset: it must land on a character boundary, otherwise a multi-byte character would be split in half causing mojibake
                if !Self::is_char_boundary(encoding_name, &original, off) {
                    return Err(e_param(
                        format!(
                            "插入偏移 {} 不在 {} 的字符边界上（会切断一个字符导致乱码）。\
                             请改用 edit_file_lines 按行插入，或修正 offset 到字符起始字节",
                            off, encoding_name
                        ),
                        None,
                    ));
                }
                let mut new_data =
                    Vec::with_capacity(original.len() + bytes.len());
                new_data.extend_from_slice(&original[..off]);
                new_data.extend_from_slice(&bytes);
                new_data.extend_from_slice(&original[off..]);
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_text_file:insert",
                    existing_bytes.as_deref(),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
                    e_internal(format!("E_WRITE insert write failed: {}", e), None)
                })?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {} | +{}B @{} | {}B | sha256:{}{}", params.path, encoding_label, bytes.len(), off, new_data.len(), Self::fingerprint_short_of_bytes(&new_data), tail))
            }
            _ => Err(e_param(
                format!("unsupported mode: {}, choose from: overwrite, append, insert", mode),
                None,
            )),
        }
        })
    }

    /// 按行号读取文本文件（与 edit_file_lines 配合使用，避免行号算错）
    #[tool(
        name = "read_text_lines",
        description = "Read text by line (1-based, with line numbers), pairs with edit_file_lines. Header includes total line count and sha256; pass the sha256 to expected_sha256 when editing to prevent concurrent overwrites",
        annotations(title = "Read text by line", read_only_hint = true)
    )]
    fn read_text_lines(
        &self,
        Parameters(params): Parameters<ReadTextLinesParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        // Reading the whole file into memory + decoding brings a 2~3x memory amplification, so cap it to avoid huge files filling memory;
        // to read a large file, use read_text_file instead (supports offset/length paging).
        // Keep error codes consistent with fs::read: file-not-found is still E_NOT_FOUND, not degraded to E_READ
        let size = match fs::metadata(&params.path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(e_internal(format!("file does not exist: {}", params.path), None));
            }
            Err(e) => return Err(e_internal(format!("failed to get file info: {}", e), None)),
        };
        if size > MAX_TEXT_LINES_FILE_SIZE {
            return Err(e_param(
                format!(
                    "file too large ({}B > {}B); read_text_lines would load it all into memory. Use read_text_file with offset/length to paginate",
                    size, MAX_TEXT_LINES_FILE_SIZE
                ),
                None,
            ));
        }
        let bytes = fs::read(&params.path).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    e_internal(format!("file does not exist: {}", params.path), None)
                }
                std::io::ErrorKind::PermissionDenied => {
                    e_internal(format!("no permission to read file: {}", params.path), None)
                }
                _ => e_internal(format!("failed to read file: {}", e), None),
            }
        })?;

        let file_size = bytes.len();
        let (encoding_name, enc_confident) = Self::resolve_encoding_with_confidence(
            params.encoding.as_deref(),
            &bytes,
        )
        .map_err(|e| e_param(e, None))?;

        // Single decode entry: strip the BOM, record the encoding (exactly the same convention as edit_file_lines)
        let ft = Self::decode_file(&bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?;
        // Line count uses the same convention as edit_file_lines (split('\n')), but does not build line content,
        // to avoid allocating Strings for millions of lines on large files; empty files are treated as 0 lines (otherwise counted as "1 empty line")
        let total_lines = if ft.content.is_empty() {
            0
        } else {
            ft.content.split('\n').count()
        };

        if total_lines == 0 {
            let sha = Self::file_fingerprint(&params.path, file_size as u64, Some(&bytes))
                .map(|h| h[..16].to_string())
                .unwrap_or_else(|| "-".to_string());
            return Ok(format!(
                "{} | {} | {}B | 0 lines total | sha256:{} | []```\n```",
                params.path,
                Self::encoding_label(&ft),
                file_size,
                sha
            ));
        }

        let start = params.start_line.unwrap_or(1).max(1);
        let end = params.end_line.unwrap_or(total_lines).min(total_lines);

        if start > end {
            return Err(e_param(
                format!("invalid line range: start_line({}) > end_line({}), total lines: {}", start, end, total_lines),
                None,
            ));
        }
        if start > total_lines {
            return Err(e_param(
                format!("start_line({}) exceeds total line count ({})", start, total_lines),
                None,
            ));
        }

        // Header warnings: invalid bytes, uncertain encoding detection
        let mut warn = String::new();
        if ft.has_invalid {
            warn.push_str(" ⚠️contains invalid bytes (replaced with U+FFFD; writing back permanently loses the original bytes; verify with a binary tool)");
        }
        if !enc_confident {
            warn.push_str(" ⚠️encoding uncertain (GBK/UTF-8 ambiguous); specify encoding explicitly and re-read");
        }

        // Line-number display width; only format the selected lines into Strings (skipped lines allocate nothing)
        let width = total_lines.to_string().len().max(3);
        let selected: Vec<String> = ft.content
            .split('\n')
            .enumerate()
            .skip(start - 1)
            .take(end - start + 1)
            .map(|(i, s)| {
                format!(
                    "{:>width$}| {}",
                    i + 1,
                    s.trim_end_matches('\r'),
                    width = width
                )
            })
            .collect();

        // 版本指纹：与写入前校验同一算法（小文件全量 sha256，大文件为 size+头尾采样）
        let sha = Self::file_fingerprint(&params.path, file_size as u64, Some(&bytes))
            .map(|h| h[..16].to_string())
            .unwrap_or_else(|| "-".to_string());

        Ok(format!(
            "{}{} | {} | {}B | {} lines total | sha256:{} | [{}-{}]```\n{}\n```",
            params.path,
            warn,
            Self::encoding_label(&ft),
            file_size,
            total_lines,
            sha,
            start,
            end,
            selected.join("\n")
        ))
    }

    /// 读取二进制文件，返回HEX dump
    #[tool(
        name = "read_binary_file",
        description = "Read a binary file as a HEX dump (offset + hex + ASCII), sliced by offset/length (max 4MB per call, truncation is flagged when exceeded). Header includes sha256",
        annotations(title = "Read binary file", read_only_hint = true)
    )]
    fn read_binary_file(
        &self,
        Parameters(params): Parameters<ReadBinaryFileParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let mut file = File::open(&params.path)
            .map_err(|e| e_internal(format!("failed to open file: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| e_internal(format!("failed to get file metadata: {}", e), None))?
            .len();

        let start = params.offset.unwrap_or(0);
        // Allow offset=0 to read an empty file (returns empty content); only error when the offset passes the end of file
        if start > 0 && start >= file_size {
            return Err(e_param(
                format!("offset={} is out of file range (file is {}B total)", start, file_size),
                None,
            ));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("seek failed: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        // Hard cap: a HEX dump is ~4-5x the original bytes, so without a limit the response would blow up
        let read_len = params
            .length
            .unwrap_or(remaining)
            .min(remaining)
            .min(MAX_BINARY_DUMP_LIMIT);
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| e_internal(format!("read failed: {}", e), None))?;

        // 格式化为经典 HEX dump 格式
        let mut hex_dump = String::new();
        for (i, chunk) in buffer.chunks(16).enumerate() {
            let offset = start + (i * 16) as u64;
            hex_dump.push_str(&format!("{:08X}  ", offset));
            for (j, byte) in chunk.iter().enumerate() {
                hex_dump.push_str(&format!("{:02X} ", byte));
                if j == 7 {
                    hex_dump.push(' ');
                }
            }
            // Pad for alignment
            if chunk.len() < 16 {
                for j in chunk.len()..16 {
                    hex_dump.push_str("   ");
                    if j == 7 {
                        hex_dump.push(' ');
                    }
                }
            }
            hex_dump.push_str(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    hex_dump.push(*byte as char);
                } else {
                    hex_dump.push('.');
                }
            }
            hex_dump.push_str("|\n");
        }

        // When this read covers the whole file (offset=0 and fully read), reuse the already-read buffer to compute the fingerprint,
        // saving path_fingerprint_short from re-reading the disk; partial reads still need to read by path.
        let sha = if start == 0 && read_len as u64 == file_size {
            Self::fingerprint_short_of_bytes(&buffer)
        } else {
            Self::path_fingerprint_short(&params.path)
        };

        // Truncation caused by the 4MB hard cap must be stated explicitly, otherwise the caller would misjudge file size from the returned length
        let trunc_warn = if (read_len as u64) < remaining as u64 {
            format!(
                " ⚠️truncated: file is {}B total ({}B remaining from offset {}), max {}B dumped per call; page the rest with offset",
                file_size, start, remaining, MAX_BINARY_DUMP_LIMIT
            )
        } else {
            String::new()
        };

        Ok(format!(
            "{} | {}B | sha256:{} | [{},{}){}```\n{}```",
            params.path,
            file_size,
            sha,
            start,
            start + read_len as u64,
            trunc_warn,
            hex_dump
        ))
    }

    /// 写入十六进制数据到二进制文件
    #[tool(
        name = "write_binary_file",
        description = "Write binary by hex. mode=overwrite (default)/append/insert (offset)/replace (offset+replace_length); offset out of range errors. \
expected_hex = pre-write check of the original bytes in the range to change (must not be empty); \
dry_run=true returns only a HEX diff preview without writing to disk",
        annotations(title = "Write binary file", destructive_hint = true)
    )]
    fn write_binary_file(
        &self,
        Parameters(params): Parameters<WriteBinaryFileParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let mode = params.mode.as_deref().unwrap_or("overwrite");
        if !matches!(mode, "overwrite" | "append" | "insert" | "replace") {
            return Err(e_param(
                format!("unsupported mode: {}, choose from: overwrite, append, insert, replace", mode),
                None,
            ));
        }
        let dry_run = params.dry_run.unwrap_or(false);
        // Same lenient parsing as expected_hex: supports 0x/0X prefix and separators like spaces/colons.
        // Empty content = 0 bytes: only replace naturally needs the "delete bytes" semantics; other modes are mostly typos
        let bytes = Self::parse_hex_flexible(&params.hex_data)
            .map_err(|e| e_param(format!("hex_data parse failed: {}", e), None))?;
        if bytes.is_empty() {
            match mode {
                // replace uses empty content to delete bytes, which is normal usage
                "replace" => {}
                "overwrite" => {
                    // overwrite would clear the file to 0 bytes, so it must be explicitly confirmed (expected_hex is the OCC check,
                    // which under overwrite requires pasting the full-file hex to pass, so it is not suitable as a confirm switch)
                    if !params.confirm.unwrap_or(false) {
                        return Err(e_param(
                            "hex_data is empty; overwrite would clear the file to 0 bytes. Pass confirm=true if you really want to clear it",
                            None,
                        ));
                    }
                }
                _ => {
                    return Err(e_param(
                        format!(
                            "hex_data is empty; under mode={} nothing would be changed (silent no-op). Provide the HEX to write; if you truly don't want to write, just skip this call",
                            mode
                        ),
                        None,
                    ));
                }
            }
        }

        // Auto-create the parent directory
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| e_internal(e, None))?;

        // Serialize read-modify-write per file + pre-write version check
        self.with_path_lock(&params.path, || {
        let current: Vec<u8> = if std::path::Path::new(&params.path).exists() {
            fs::read(&params.path).map_err(|e| {
                e_internal(format!("failed to read the original file: {}", e), None)
            })?
        } else {
            Vec::new()
        };
        Self::check_expected_sha(&params.path, &current, params.expected_sha256.as_deref())?;

        // Pre-write compare the actual bytes of "the range to change": binaries have no line numbers/anchors, so a wrong offset can only be caught here
        if let Some(exp_hex) = params.expected_hex.as_deref() {
            // Empty expected_hex = "no check", but would make one think it was checked (0 bytes always matches) -> reject explicitly
            if exp_hex.trim().is_empty() {
                return Err(e_param(
                    "expected_hex must not be empty: an empty string means no check. If you don't need a check, omit the parameter entirely",
                    None,
                ));
            }
            let expected = Self::parse_hex_flexible(exp_hex)
                .map_err(|e| e_param(format!("expected_hex parse failed: {}", e), None))?;
            let (actual, scope) = Self::binary_guard_range(
                &current,
                mode,
                params.offset,
                params.replace_length,
                expected.len(),
            );
            if actual != expected {
                return Err(e_param(
                    format!(
                        "expected_hex check failed: the original bytes in the range to change do not match the expectation (offset/replace_length may be miscalculated).\n\
                         === actual bytes of range [{}]:\n{}\n=== bytes you expected:\n{}",
                        scope,
                        Self::hex_preview(&actual),
                        Self::hex_preview(&expected)
                    ),
                    None,
                ));
            }
        }

        // Compute "post-change bytes" first: real write and dry_run preview share the same logic, to avoid divergence between the two
        let (new_data, action) = match mode {
            "overwrite" => (bytes.clone(), format!("{}B", bytes.len())),
            "append" => {
                let mut v = current.clone();
                v.extend_from_slice(&bytes);
                (v, format!("+{}B append", bytes.len()))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                if off > current.len() {
                    return Err(e_param(
                        format!(
                            "insert offset={} exceeds file size {}B; use read_binary_file to confirm the real length first, then retry",
                            off,
                            current.len()
                        ),
                        None,
                    ));
                }
                let mut v = Vec::with_capacity(current.len() + bytes.len());
                v.extend_from_slice(&current[..off]);
                v.extend_from_slice(&bytes);
                v.extend_from_slice(&current[off..]);
                (v, format!("+{}B @{}", bytes.len(), off))
            }
            "replace" => {
                let off = params.offset.unwrap_or(0) as usize;
                let replace_len = params.replace_length.unwrap_or(0);
                if off > current.len() {
                    return Err(e_param(
                        format!("replace offset={} exceeds file size {}B", off, current.len()),
                        None,
                    ));
                }
                // checked_add prevents offset + replace_length from overflowing and bypassing the bounds check
                let end = match off.checked_add(replace_len) {
                    Some(end) if end <= current.len() => end,
                    _ => {
                        return Err(e_param(
                            format!(
                                "replace range out of bounds: offset={} + replace_length={} exceeds file size {}B.\
                                 Re-check the offset (use read_binary_file to see the real content), or reduce replace_length",
                                off,
                                replace_len,
                                current.len()
                            ),
                            None,
                        ));
                    }
                };
                let mut v = Vec::with_capacity(off + bytes.len() + (current.len() - end));
                v.extend_from_slice(&current[..off]);
                v.extend_from_slice(&bytes);
                v.extend_from_slice(&current[end..]);
                (v, format!("{}B→{}B @{}", replace_len, bytes.len(), off))
            }
            other => {
                return Err(e_param(format!("unsupported mode: {}", other), None));
            }
        };

        // dry_run：只返回 diff 预览，不落盘
        if dry_run {
            return Ok(Self::binary_dry_run_report(
                &params.path,
                &current,
                &new_data,
                &action,
            ));
        }

        match mode {
            "overwrite" => {
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:overwrite",
                    Some(&current),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path()))
                    .map_err(|e| e_internal(format!("E_WRITE write failed: {}", e), None))?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {}B | sha256:{}{}", params.path, new_data.len(), Self::fingerprint_short_of_bytes(&new_data), tail))
            }
            // Append still uses O_APPEND (to avoid rewriting the whole large file); new_data is only used for the fingerprint
            "append" => {
                retry_io(|| {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&params.path)?;
                    file.write_all(&bytes)?;
                    file.flush()?;
                    Ok(())
                })
                .map_err(|e| e_internal(format!("E_WRITE append failed: {}", e), None))?;
                Ok(format!("OK {} | +{}B append | sha256:{}", params.path, bytes.len(), Self::fingerprint_short_of_bytes(&new_data)))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:insert",
                    Some(&current),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
                    e_internal(format!("E_WRITE insert write failed: {}", e), None)
                })?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | +{}B @{} | {}B | sha256:{}{}", params.path, bytes.len(), off, new_data.len(), Self::fingerprint_short_of_bytes(&new_data), tail))
            }
            "replace" => {
                let off = params.offset.unwrap_or(0) as usize;
                let replace_len = params.replace_length.unwrap_or(0);
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:replace",
                    Some(&current),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
                    e_internal(format!("E_WRITE replace write failed: {}", e), None)
                })?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }

                Ok(format!(
                    "OK {} | {}B→{}B @{} | {}B | sha256:{}{}",
                    params.path,
                    replace_len,
                    bytes.len(),
                    off,
                    new_data.len(),
                    Self::fingerprint_short_of_bytes(&new_data),
                    tail
                ))
            }
            other => Err(e_param(format!("unsupported mode: {}", other), None)),
        }
        })
    }

    /// 搜索文件/目录中的文本内容(正则)
    #[tool(
        name = "text_search",
        description = "Search text in a file/directory. mode=regex (default, regex)/literal (plain text, pattern needs no escaping). \
Results are grouped by file (include sha256, usable directly as edit_file_lines' expected_sha256); each is line:col:[hit fragment] \"full line\". \
Directories recurse by default and auto-skip hidden files/dirs (.git/.env etc.; skip_hidden=false turns this off). When extension/extensions/include are not given, \
binary/build artifacts (.dcu/.exe/.res/.dll/.bak/.pyc etc.) are skipped by default to focus the budget on source; use extension/extensions, \
include/exclude (glob) to control scope; max_files (default 20000) is the coverage cap on "how many candidate files to scan" (hitting it warns, it is NOT the number of matches returned), \
max_results (default 100) is the "max number of matching lines to return"; encoding defaults to auto (per-file detection, distinguishes GBK/UTF-8); context_lines>0 attaches context lines",
        annotations(title = "Text search", read_only_hint = true)
    )]
    fn text_search(
        &self,
        Parameters(params): Parameters<TextSearchParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let case_sensitive = params.case_sensitive.unwrap_or(true);
        let max_results = params.max_results.unwrap_or(100).max(1);
        let recursive = params.recursive.unwrap_or(true);
        let context_lines = params.context_lines.unwrap_or(0);
        let skip_hidden = params.skip_hidden.unwrap_or(true);
        // Default regex (keep existing behavior); in literal mode treat the pattern as plain text
        let literal = match params.mode.as_deref() {
            None | Some("") => false,
            Some(m) if m.eq_ignore_ascii_case("literal") => true,
            Some(m) if m.eq_ignore_ascii_case("regex") => false,
            Some(m) => {
                return Err(e_param(
                    format!("unsupported mode: {}, choose from: regex (default), literal", m),
                    None,
                ))
            }
        };
        // An empty pattern would match every position of every line (producing lots of meaningless hits), so reject it
        if params.pattern.is_empty() {
            return Err(e_param(
                "pattern must not be empty; provide the text or regex to search for".to_string(),
                None,
            ));
        }
        // Default auto: consistent with read_text_file, detect encoding per file (can distinguish GBK/UTF-8)
        let encoding_raw = params.encoding.as_deref();
        let encoding_auto = Self::encoding_is_auto(encoding_raw);

        // In literal mode escape regex metacharacters: the AI often passes plain text containing . * [ directly, to avoid being mis-matched as a regex
        let pattern_str = if literal {
            regex::escape(&params.pattern)
        } else {
            params.pattern.clone()
        };
        let pattern_str = if case_sensitive {
            pattern_str
        } else {
            format!("(?i){}", pattern_str)
        };

        let re = Regex::new(&pattern_str).map_err(|e| {
            e_param(format!("regex error: {}", e), None)
        })?;

        // Extension filtering (strip a possible . prefix; extension and extensions can be combined, taking the union)
        let mut ext_list: Vec<String> = Vec::new();
        for e in params.extension.iter().chain(
            params.extensions.iter().flatten(),
        ) {
            let e = e.trim_start_matches('.').to_lowercase();
            if !e.is_empty() && !ext_list.contains(&e) {
                ext_list.push(e);
            }
        }
        // Scope filtering in directory mode: include (whitelist) / exclude (blacklist), both glob
        let include = Self::compile_globs(&params.include, "include")?;
        let exclude = Self::compile_globs(&params.exclude, "exclude")?;

        let path = std::path::Path::new(&params.path);
        let is_dir = path.is_dir();

        // When extension/extensions/include are not given, enable "default binary skip" to focus the budget on source text
        let default_skip = ext_list.is_empty() && include.is_none();

        // Collect the list of files to search (the file count cap is controlled independently; hitting it is warned explicitly rather than silently swallowed).
        // The default cap is set fairly high (2000), so source files in a large directory aren't capped away behind binaries/build artifacts;
        // it can still be overridden explicitly via max_files.
        let max_files = params.max_files.unwrap_or(20000).max(1);
        let mut files: Vec<String> = Vec::new();
        let mut scan = SearchScanStat::default();
        if is_dir {
            Self::collect_files(
                path, path, &ext_list, &include, &exclude, recursive, skip_hidden, default_skip,
                max_files, &mut files, &mut scan,
            )
            .map_err(|e| e_internal(e, None))?;
        } else {
            files.push(params.path.clone());
        }

        let mut blocks: Vec<String> = Vec::new();   // One output block per matched file
        let mut stored = 0usize;                    // Number of hits already returned
        let mut found = 0usize;                     // Total hits inside already-read files (may exceed stored)
        let mut searched_files = 0usize;
        let mut matched_files = 0usize;
        let mut skipped: Vec<String> = Vec::new();  // Files that failed to read/decode, with reasons

        for file_path in &files {
            if stored >= max_results {
                break;
            }
            searched_files += 1;

            // Read + decode (failures are no longer silently skipped; count them in skipped for the caller to diagnose)
            let (enc_label, content, raw_bytes) =
                match Self::read_search_content(file_path, encoding_raw, encoding_auto) {
                    Ok(v) => v,
                    Err(reason) => {
                        skipped.push(format!("{} ({})", file_path, reason));
                        continue;
                    }
                };
            struct Hit<'a> {
                line_idx: usize,
                col: usize,
                text: String,
                line_text: &'a str,
            }
            // Beyond max_results, stop storing but keep counting, so the true total hit count can be reported.
            // Stream content.lines() directly instead of collecting the whole line vector on the first hit (saves memory on large files)
            let mut hits: Vec<Hit<'_>> = Vec::new();
            for (line_idx, line) in content.lines().enumerate() {
                for mat in re.find_iter(line) {
                    found += 1;
                    if stored + hits.len() >= max_results {
                        continue;
                    }
                    // Column number counts characters (was byte offset before, which misaligned on Chinese lines)
                    let col = line[..mat.start()].chars().count() + 1;
                    hits.push(Hit {
                        line_idx,
                        col,
                        text: mat.as_str().to_string(),
                        line_text: line,
                    });
                }
            }
            if hits.is_empty() {
                continue;
            }
            matched_files += 1;
            let stored_in_file = hits.len();
            stored += stored_in_file;

            // The file block header carries sha256, directly reusable as edit_file_lines' expected_sha256.
            // The fingerprint is computed only when there is an actual hit: candidate files that don't match don't do a pointless full hash.
            let mut block = format!(
                "{} | sha256:{} | enc:{} | {} matches",
                file_path,
                Self::fingerprint_short_of_bytes(&raw_bytes),
                enc_label,
                stored_in_file
            );

            if context_lines == 0 {
                for h in &hits {
                    block.push_str(&format!(
                        "\n  {}:{}  [{}] \"{}\"",
                        h.line_idx + 1,
                        h.col,
                        h.text,
                        Self::clip_line(h.line_text)
                    ));
                }
            } else {
                // Context mode needs index access to neighboring lines, so the line vector is collected only then
                let lines: Vec<&str> = content.lines().collect();
                // Merge adjacent context ranges; the same line is output only once
                let mut ranges: Vec<(usize, usize)> = Vec::new();
                for h in &hits {
                    let s = h.line_idx.saturating_sub(context_lines);
                    let e = (h.line_idx + context_lines).min(lines.len().saturating_sub(1));
                    let mut merged = false;
                    if let Some(last) = ranges.last_mut() {
                        if s <= last.1 + 1 {
                            if e > last.1 {
                                last.1 = e;
                            }
                            merged = true;
                        }
                    }
                    if !merged {
                        ranges.push((s, e));
                    }
                }
                for (s, e) in ranges {
                    block.push_str("\n  --");
                    for idx in s..=e {
                        let marks: Vec<String> = hits
                            .iter()
                            .filter(|h| h.line_idx == idx)
                            .map(|h| format!("[{}]@{}", h.text, h.col))
                            .collect();
                        let line_text = Self::clip_line(lines[idx]);
                        if marks.is_empty() {
                            block.push_str(&format!("\n   {:>5}| {}", idx + 1, line_text));
                        } else {
                            block.push_str(&format!(
                                "\n > {:>5}| {}  {}",
                                idx + 1,
                                line_text,
                                marks.join(" ")
                            ));
                        }
                    }
                }
            }
            blocks.push(block);
        }

        let mut warnings: Vec<String> = Vec::new();
        if found > stored {
            warnings.push(format!(
                "⚠️ too many hits: only the first {} returned ({} matches within the scanned range). Raise max_results, or narrow with include/exclude/extension and retry",
                stored, found
            ));
        }
        if scan.capped {
            let mut reason = format!(
                "collected {}; another {} candidates were filtered out by include/exclude/extension/hidden",
                files.len(), scan.filtered
            );
            if scan.default_filtered > 0 {
                reason.push_str(&format!(
                    ", {} binaries/build artifacts were skipped by default (specify extension/include to force them in)",
                    scan.default_filtered
                ));
            }
            warnings.push(format!(
                "⚠️ candidate files hit the cap {}; the directory may not be fully covered ({}). Raise max_files or narrow the scope and retry",
                max_files, reason
            ));
        }
        if !skipped.is_empty() {
            let shown: Vec<String> = skipped.iter().take(5).cloned().collect();
            warnings.push(format!(
                "⚠️ {} files could not be searched: {}\n   (common causes: binary/non-text content, file too large, or mismatch with the explicitly specified encoding; retry with the correct encoding)",
                skipped.len(),
                shown.join("\n   ")
            ));
        }

        let mut extras: Vec<String> = Vec::new();
        if !ext_list.is_empty() {
            extras.push(format!(
                "ext:{}",
                ext_list
                    .iter()
                    .map(|e| format!(".{}", e))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if literal {
            extras.push("mode:literal".to_string());
        }
        if is_dir && !skip_hidden {
            extras.push("hidden:included".to_string());
        }
        if let Some(ref inc) = params.include {
            if !inc.is_empty() {
                extras.push(format!("include:{}", inc.join(",")));
            }
        }
        if let Some(ref exc) = params.exclude {
            if !exc.is_empty() {
                extras.push(format!("exclude:{}", exc.join(",")));
            }
        }
        if scan.pruned_dirs > 0 {
            extras.push(format!("pruned_dirs:{}", scan.pruned_dirs));
        }
        if context_lines > 0 {
            extras.push(format!("ctx:{}", context_lines));
        }
        if !skipped.is_empty() {
            extras.push(format!("skipped:{}", skipped.len()));
        }

        // 命中数：未截断直接给总数；截断时写成 返回数/已扫描到的实际数 并显式标注 truncated
        let matches_label = if found > stored {
            format!("{}/{} matches(truncated)", stored, found)
        } else {
            format!("{} matches", found)
        };

        let mut out = format!(
            "{} | {} | {} | {}/{} files | {}{}```",
            params.path,
            params.pattern,
            if case_sensitive { "cs" } else { "ci" },
            matched_files,
            searched_files,
            matches_label,
            if extras.is_empty() {
                String::new()
            } else {
                format!(" | {}", extras.join(" | "))
            }
        );
        if blocks.is_empty() {
            out.push_str("\n(no matches)");
        } else {
            out.push('\n');
            out.push_str(&blocks.join("\n"));
        }
        for w in &warnings {
            out.push('\n');
            out.push_str(w);
        }
        out.push_str("\n```");
        Ok(out)
    }

    /// 批量原子片段编辑：一次调用完成多处"精确文本 → 新文本"替换
    #[tool(
        name = "edit_file_sections",
        description = "Change multiple places in one call (all-or-nothing by default): edits=[{expected_old, content, occurrence?, start_line?}]. \
expected_old must match character-by-character and be unique in the file by default; for multiple hits use occurrence or start_line (a wrong value reports the actual line); an empty content deletes. \
Located against a single snapshot; overlaps error out; supports expected_sha256 and dry_run; the second line of the header gives the line number of each change",
        annotations(title = "Batch section edit", destructive_hint = true)
    )]
    fn edit_file_sections(
        &self,
        Parameters(params): Parameters<EditFileSectionsParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        if params.edits.is_empty() {
            return Err(e_param(
                "edits must not be empty: provide at least one {expected_old, content}",
                None,
            ));
        }

        // Same protection as regex_replace: the whole file is read into memory and rebuilt, so overly large files should be split first
        let file_size = fs::metadata(&params.path)
            .map_err(|e| e_internal(format!("failed to get file info: {}", e), None))?
            .len();
        if file_size > MAX_REGEX_FILE_SIZE {
            return Err(e_param(
                format!(
                    "file too large ({}B), max supported is {}B. To process a large file, split it manually first",
                    file_size, MAX_REGEX_FILE_SIZE
                ),
                None,
            ));
        }

        let all_or_nothing = params.all_or_nothing.unwrap_or(true);
        self.with_path_lock(&params.path, || {
            let bytes = fs::read(&params.path)
                .map_err(|e| e_internal(format!("failed to read file: {}", e), None))?;
            Self::check_expected_sha(&params.path, &bytes, params.expected_sha256.as_deref())?;

            // 与 write_text_file/regex_replace 同一套编码决策：默认保持原编码，不一致时拒绝
            let encoding_name = Self::resolve_write_encoding(
                &params.path,
                params.encoding.as_deref(),
                Some(&bytes),
            )?;
            if Self::encoding_is_auto(params.encoding.as_deref()) {
                Self::check_encoding_lossless(encoding_name, &bytes)?;
            }

            let ft = Self::decode_file(&bytes, encoding_name).map_err(|e| e_internal(e, None))?;
            if ft.has_invalid {
                return Err(e_internal(
                    format!(
                        "文件 {} 按 {} 解码时存在非法字节（已用 U+FFFD 替换），拒绝写回以免原字节永久丢失。\
                         请确认真实编码后用正确的 encoding 重新调用",
                        params.path, ft.encoding
                    ),
                    None,
                ));
            }
            let encoding_label = if ft.bom.is_empty() {
                ft.encoding.clone()
            } else {
                format!("{}(BOM)", ft.encoding)
            };

            // 统一到 LF 再匹配：AI 读到的文本可能带/不带 \r，两侧归一后更稳（写回时还原主换行风格）
            let hay = ft.content.replace("\r\n", "\n");

            // ---- 第一步：所有片段都在**原文快照**上定位，而不是"改一个再找下一个" ----
            let mut planned: Vec<PlannedSection> = Vec::new();
            let mut problems: Vec<String> = Vec::new();
            for (idx, op) in params.edits.iter().enumerate() {
                let needle = op.expected_old.replace("\r\n", "\n");
                if needle.is_empty() {
                    problems.push(format!(
                        "edits[{}]: expected_old 不能为空（要插入内容请把插入点周围的原文一并作为 expected_old，并在 content 里原样带上它）",
                        idx
                    ));
                    continue;
                }
                let mut hits = Self::find_all(&hay, &needle);
                // 可选的行号约束（文本 + 行号双约束）：只承认"从声明的第 start_line 行开始"的命中。
                // 既能消歧（同一片段出现多次），也能在行号算错时直接告诉调用方它实际在第几行。
                if let Some(k) = op.start_line {
                    let pinned: Vec<(usize, usize)> = hits
                        .iter()
                        .copied()
                        .filter(|(s, _)| Self::line_of(&hay, *s) == k)
                        .collect();
                    if pinned.is_empty() {
                        let spots: Vec<String> = hits
                            .iter()
                            .take(10)
                            .map(|(s, _)| format!("第 {} 行", Self::line_of(&hay, *s)))
                            .collect();
                        problems.push(if spots.is_empty() {
                            format!(
                                "edits[{}]: expected_old 与文件内容不匹配（全文件均未命中，第 {} 行自然也没有）。\
                                 它必须与原文逐字符一致（含缩进、空行、标点）；建议先用 read_text_lines 读出准确文本再复制过来",
                                idx, k
                            )
                        } else {
                            format!(
                                "edits[{}]: start_line={} 与 expected_old 的实际位置不一致：它出现在 {}。\
                                 请修正 start_line，或删掉 start_line 让它按默认的唯一性规则定位",
                                idx, k, spots.join("、")
                            )
                        });
                        continue;
                    }
                    hits = pinned;
                }
                let chosen = match hits.len() {
                    0 => None,
                    1 if op.occurrence.is_none() => Some(hits[0]),
                    n => match op.occurrence {
                        Some(k) if k >= 1 && (k as usize) <= n => Some(hits[k as usize - 1]),
                        Some(k) => {
                            problems.push(format!(
                                "edits[{}]: occurrence={} 超出范围（expected_old 只命中 {} 处）",
                                idx, k, n
                            ));
                            continue;
                        }
                        None => {
                            let spots: Vec<String> = hits
                                .iter()
                                .take(10)
                                .map(|(s, _)| format!("第 {} 行", Self::line_of(&hay, *s)))
                                .collect();
                            let more = if hits.len() > 10 { " 等" } else { "" };
                            problems.push(format!(
                                "edits[{}]: expected_old 在文件中不唯一（命中 {} 处：{}{}），无法确定要改哪一处。\
                                 请把 expected_old 写得更长以唯一定位，或用 occurrence 指定第几处，或用 start_line 声明它从第几行开始",
                                idx, n, spots.join("、"), more
                            ));
                            continue;
                        }
                    },
                };
                match chosen {
                    Some((s, e)) => {
                        // 记下该片段在**改动前**原文中的行区间，供返回头回报落点。
                        // 结束行只能用"匹配文本里的换行数"推算：不能用 e-1（多字节字符的
                        // 最后一个字节不在字符边界上，切片会 panic）。
                        let line_from = Self::line_of(&hay, s);
                        let nl = hay[s..e].matches('\n').count();
                        let line_to = if nl > 0 && hay.as_bytes()[e - 1] == b'\n' {
                            line_from + nl - 1
                        } else {
                            line_from + nl
                        };
                        planned.push(PlannedSection {
                            start: s,
                            end: e,
                            repl: op.content.replace("\r\n", "\n"),
                            idx,
                            line_from,
                            line_to,
                        });
                    }
                    None => problems.push(format!(
                        "edits[{}]: expected_old 与文件内容不匹配（未命中）。\
                         它必须与原文逐字符一致（含缩进、空行、标点）；建议先用 read_text_lines 读出准确文本再复制过来",
                        idx
                    )),
                }
            }

            if !problems.is_empty() && (all_or_nothing || planned.is_empty()) {
                // 显式指定错误码：混合原因时按"命中不唯一"优先，便于调用方分流
                let code = if problems.iter().all(|p| p.contains("不唯一")) {
                    "E_NOT_UNIQUE"
                } else {
                    "E_GUARD_MISMATCH"
                };
                return Err(e_param(
                    format!(
                        "{} 批量编辑未通过校验，本次一处未改（{} 条问题，{} 条可应用）。\n=== 问题清单:\n{}",
                        code,
                        problems.len(),
                        planned.len(),
                        problems.join("\n")
                    ),
                    None,
                ));
            }

            // ---- 第二步：重叠检测（同一段被两条编辑改会得到意料之外的结果） ----
            planned.sort_by_key(|p| p.start);
            for w in planned.windows(2) {
                if w[1].start < w[0].end {
                    return Err(e_param(
                        format!(
                            "edits[{}] 与 edits[{}] 的命中范围重叠（参数错误），无法同时应用。请合并为一条，或让两条片段的命中区间互不相交",
                            w[0].idx, w[1].idx
                        ),
                        None,
                    ));
                }
            }

            // ---- 第三步：按快照一次性拼接 ----
            let mut new_content = String::with_capacity(hay.len());
            let mut cursor = 0usize;
            for p in &planned {
                new_content.push_str(&hay[cursor..p.start]);
                new_content.push_str(&p.repl);
                cursor = p.end;
            }
            new_content.push_str(&hay[cursor..]);
            let new_content = if ft.line_ending == "\n" {
                new_content
            } else {
                new_content.replace('\n', ft.line_ending)
            };

            let new_bytes = {
                let mut out: Vec<u8> = ft.bom.to_vec();
                out.extend_from_slice(
                    &Self::encode_content(&ft.encoding, &new_content)
                        .map_err(|e| e_internal(e, None))?,
                );
                out
            };

            // 被跳过的条目（all_or_nothing=false 时才有）：dry-run 也必须能看到，
            // 否则"先预览再决定"就失去了意义
            let skip_note = if problems.is_empty() {
                String::new()
            } else {
                format!(
                    "\n⚠️ skipped {} (all_or_nothing=false):\n{}",
                    problems.len(),
                    problems.join("\n")
                )
            };

            if params.dry_run.unwrap_or(false) {
                return Ok(format!(
                    "DRY-RUN | {} | {} | {} 处替换 | {}B→{}B | 未写入文件\n{}\n{}预计 sha256:{}\n确认无误后去掉 dry_run 重新调用即可写入{}",
                    params.path,
                    encoding_label,
                    planned.len(),
                    bytes.len(),
                    new_bytes.len(),
                    Self::format_section_positions(&planned),
                    Self::sections_diff(&ft.content, &planned, 1),
                    Self::fingerprint_short_of_bytes(&new_bytes),
                    skip_note
                ));
            }

            let bak = Self::backup_before_write(&params.path, "edit_file_sections", Some(&bytes));
            Self::atomic_write_ex(&params.path, &new_bytes, bak.as_ref().map(|b| b.bak.as_path()))
                .map_err(|e| e_internal(format!("E_WRITE write failed: {}", e), None))?;
            let mut tail = String::new();
            if let Some(h) = &bak {
                Self::finish_backup(h, &new_bytes);
                tail = " | undoable".to_string();
            }
            Ok(format!(
                "OK {} | {} | {} 处替换 | {}B→{}B | sha256:{}{}\n{}{}",
                params.path,
                encoding_label,
                planned.len(),
                bytes.len(),
                new_bytes.len(),
                Self::fingerprint_short_of_bytes(&new_bytes),
                tail,
                // 落点行号（改动前）：便于调用方核对"改的是不是我说的那几处"，不必再读一次文件
                Self::format_section_positions(&planned),
                skip_note
            ))
        })
    }


    /// 正则替换文件文本
    #[tool(
        name = "regex_replace",
        description = "Regex replace (supports $1/$2); literal=true = plain-text replace (no escaping, $ taken literally). max_matches is required = expected max replacements, rejected if exceeded; global defaults to true; dry_run=true returns only a diff",
        annotations(title = "Regex replace", destructive_hint = true)
    )]
    fn regex_replace(
        &self,
        Parameters(params): Parameters<RegexReplaceParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };

        // 检查文件大小，避免大文件导致 OOM
        let file_size = fs::metadata(&params.path)
            .map_err(|e| e_internal(format!("failed to get file info: {}", e), None))?
            .len();
        if file_size > MAX_REGEX_FILE_SIZE {
            return Err(e_param(
                format!(
                    "文件过大 ({}B)，最大支持 {}B。如需处理大文件，请手动分割后操作",
                    file_size, MAX_REGEX_FILE_SIZE
                ),
                None,
            ));
        }

        // 同一文件的读-改-写串行化 + 写前版本校验
        self.with_path_lock(&params.path, || {
        let bytes = fs::read(&params.path).map_err(|e| {
            e_internal(format!("failed to read file: {}", e), None)
        })?;
        Self::check_expected_sha(&params.path, &bytes, params.expected_sha256.as_deref())?;

        // 与 write_text_file/edit_file_lines 同一套编码决策：未指定则自动检测并保持原编码写回；
        // 显式指定且与实际编码不一致时直接拒绝，避免把 GBK/UTF-16 文件改写成另一种编码
        let encoding_name = Self::resolve_write_encoding(
            &params.path,
            params.encoding.as_deref(),
            Some(&bytes),
        )?;

        // 统一解码：剥离 BOM 并记住 BOM/编码，写回时原样补回
        let ft = Self::decode_file(&bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?;
        let FileText { encoding, bom, line_ending, content, has_invalid } = ft;
        // 解码时替换过非法字节的内容不允许写回，否则原字节被永久破坏
        if has_invalid {
            return Err(e_internal(
                format!(
                    "文件 {} 按 {} 解码时存在非法字节（已用 U+FFFD 替换），拒绝写回以免原字节永久丢失。\
                     请确认文件真实编码后用正确的 encoding 重新调用",
                    params.path, encoding
                ),
                None,
            ));
        }
        let encoding_label = if bom.is_empty() {
            encoding.clone()
        } else {
            format!("{}(BOM)", encoding)
        };

        // literal=true：pattern 按纯文本处理（转义后再编译），replacement 里的 $ 也转成字面量。
        // 这样"把 A 精确换成 B"不需要任何正则知识，也不会被元字符/捕获组引用坑到。
        let literal = params.literal.unwrap_or(false);
        if literal && params.pattern.is_empty() {
            return Err(e_param(
                "literal 模式下 pattern 不能为空（空串会匹配任意位置）",
                None,
            ));
        }
        let pattern_src = if literal {
            regex::escape(&params.pattern)
        } else {
            params.pattern.clone()
        };
        let re = Regex::new(&pattern_src).map_err(|e| {
            e_param(format!("正则表达式错误: {}", e), None)
        })?;
        let repl: String = if literal {
            params.replacement.replace('$', "$$")
        } else {
            params.replacement.clone()
        };

        let global = params.global.unwrap_or(true);
        // max_matches 必须显式设置：强制 AI 先想清楚"预期改几处"，避免过宽正则/匹配空串造成大范围误替换
        let max_matches = params.max_matches.ok_or_else(|| {
            e_param(
                "regex_replace 必须显式设置 max_matches（本次预期最多替换几处）。\
                 请先估算预期匹配数后传入该上限，例如 max_matches=1 表示只允许改 1 处；\
                 实际匹配数超过该值时会被拒绝，防止正则过宽或匹配空串导致大范围误替换。".to_string(),
                None,
            )
        })?;
        if max_matches == 0 {
            return Err(e_param(
                "max_matches 必须大于 0（若为 0 请直接不调用本工具）".to_string(),
                None,
            ));
        }

        // 计算匹配数（带上限，防止匹配空串/过宽正则时计数爆炸）
        let count = if global {
            re.find_iter(&content).take(max_matches + 1).count()
        } else {
            if re.is_match(&content) { 1 } else { 0 }
        };

        if count == 0 {
            return Ok(format!("{} | {} | 0", params.path, params.pattern));
        }
        if count > max_matches {
            return Err(e_param(
                format!(
                    "匹配数量 {} 超过你设置的上限 {}，拒绝执行！请检查正则是否过宽或匹配了空串。\
                     确认无误可重新调用并把 max_matches 调高到预期值",
                    count, max_matches
                ),
                None,
            ));
        }

        let new_content = if global {
            re.replace_all(&content, repl.as_str()).into_owned()
        } else {
            re.replacen(&content, 1, repl.as_str()).into_owned()
        };

        // dry-run：只预览不写入
        if params.dry_run.unwrap_or(false) {
            let mut preview = String::new();
            for (i, mat) in re.find_iter(&content).take(20).enumerate() {
                let replaced = re
                    .captures_at(&content, mat.start())
                    .map(|caps| {
                        let mut out = String::new();
                        caps.expand(repl.as_str(), &mut out);
                        out
                    })
                    .unwrap_or_else(|| repl.clone());
                preview.push_str(&format!(
                    "  #{}: \"{}\" => \"{}\"\n",
                    i + 1,
                    mat.as_str(),
                    replaced
                ));
            }
            if count > 20 {
                preview.push_str(&format!("  ... 共 {} 处匹配，仅预览前 20 处\n", count));
            }
            return Ok(format!(
                "{} | DRY-RUN | {} | {} matches | 未写入文件\n{}新文件大小: {}B → {}B\n确认无误后去掉 dry_run 重新调用以实际写入",
                params.path,
                params.pattern,
                count,
                preview,
                content.len(),
                new_content.len()
            ));
        }

        // 按原编码编码回字节，并原样补回 BOM
        let new_bytes = Self::encode_file(&FileText {
            encoding: encoding.clone(),
            bom,
            line_ending,
            content: new_content,
            has_invalid: false,
        })
        .map_err(|e| e_internal(e, None))?;

        let bak = Self::backup_before_write(&params.path, "regex_replace", Some(&bytes));
        Self::atomic_write_ex(&params.path, &new_bytes, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
            e_internal(format!("E_WRITE write file failed: {}", e), None)
        })?;
        let mut tail = String::new();
        if let Some(h) = &bak {
            Self::finish_backup(h, &new_bytes);
            tail = " | undoable".to_string();
        }

        Ok(format!(
            "{} | {} | {} | {} matches | {}B→{}B | sha256:{}{}",
            params.path,
            encoding_label,
            params.pattern,
            count,
            content.len(),
            new_bytes.len(),
            Self::fingerprint_short_of_bytes(&new_bytes),
            tail
        ))
        })
    }

    /// 列出或搜索目录内容
    #[tool(
        name = "list_files",
        description = "List a directory / search by file name (glob_pattern or pattern regex, choose one), with recursive, include_dirs, show_size/show_modified",
        annotations(title = "List directory", read_only_hint = true)
    )]
    fn list_files(
        &self,
        Parameters(params): Parameters<ListFilesParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let recursive = params.recursive.unwrap_or(false);
        let include_dirs = params.include_dirs.unwrap_or(true);
        // max_results=0 会让工具"立即截断返回空"，这里兜到至少 1，避免空结果难以归因
        let max_results = params.max_results.unwrap_or(500).max(1);
        let show_size = params.show_size.unwrap_or(true);
        let show_modified = params.show_modified.unwrap_or(false);

        let re = match &params.pattern {
            Some(p) => Some(Regex::new(p).map_err(|e| {
                e_param(format!("正则表达式错误: {}", e), None)
            })?),
            None => None,
        };

        let glob_matcher = match &params.glob_pattern {
            Some(g) => {
                if params.pattern.is_some() {
                    return Err(e_param("pattern 和 glob_pattern 不能同时使用", None));
                }
                let glob = Glob::new(g).map_err(|e| {
                    e_param(format!("Glob 表达式错误: {}", e), None)
                })?;
                Some(glob.compile_matcher())
            }
            None => None,
        };

        let mut entries = Vec::new();
        let mut file_count = 0usize;
        let mut dir_count = 0usize;
        let mut scanned_dirs = 0usize;
        let mut total_size = 0u64;
        let mut truncated_flag = false;

        fn fmt_modified(entry: &std::fs::DirEntry) -> String {
            entry.metadata().ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| format!("{}s", d.as_secs()))
                .unwrap_or_default()
        }

        fn scan_dir(
            dir_path: &std::path::Path,
            re: &Option<Regex>,
            glob_matcher: &Option<GlobMatcher>,
            recursive: bool,
            include_dirs: bool,
            max_results: usize,
            show_size: bool,
            show_modified: bool,
            entries: &mut Vec<(String, bool, u64, String)>,
            file_count: &mut usize,
            dir_count: &mut usize,
            scanned_dirs: &mut usize,
            total_size: &mut u64,
            truncated: &mut bool,
        ) -> Result<(), String> {
            *scanned_dirs += 1;
            let entries_dir = fs::read_dir(dir_path)
                .map_err(|e| format!("cannot read directory {}: {}", dir_path.display(), e))?;
            let mut sorted: Vec<_> = entries_dir.filter_map(|e| e.ok()).collect();
            sorted.sort_by_cached_key(|e| e.file_name());
            for entry in sorted {
                if entries.len() >= max_results {
                    *truncated = true;
                    return Ok(());
                }
                let name = entry.file_name().to_string_lossy().to_string();
                // 跳过本工具自己产生的临时文件与锁文件
                if is_internal_file(&name) { continue; }
                let ft = entry.file_type().ok();
                let is_dir = ft.as_ref().map(|t| t.is_dir()).unwrap_or(false);
                let is_file = ft.as_ref().map(|t| t.is_file()).unwrap_or(false);

                if is_dir && recursive {
                    scan_dir(
                        &entry.path(), re, glob_matcher, recursive, include_dirs, max_results,
                        show_size, show_modified, entries, file_count, dir_count,
                        scanned_dirs, total_size, truncated,
                    )?;
                    if entries.len() >= max_results {
                        *truncated = true;
                        return Ok(());
                    }
                }

                // 匹配：正则 / glob / 全部列出
                let matched = match re {
                    Some(re) => re.is_match(&name),
                    None => match glob_matcher {
                        Some(gm) => gm.is_match(&name),
                        None => true,
                    },
                };
                if !matched { continue; }

                let is_entry_dir = is_dir;
                if is_entry_dir {
                    if include_dirs {
                        let modified = if show_modified { fmt_modified(&entry) } else { String::new() };
                        entries.push((entry.path().to_string_lossy().to_string(), true, 0, modified));
                        *dir_count += 1;
                    }
                } else if is_file {
                    let size = if show_size { entry.metadata().ok().map(|m| m.len()).unwrap_or(0) } else { 0 };
                    if show_size { *total_size += size; }
                    let modified = if show_modified { fmt_modified(&entry) } else { String::new() };
                    entries.push((entry.path().to_string_lossy().to_string(), false, size, modified));
                    *file_count += 1;
                }
            }
            Ok(())
        }

        scan_dir(
            std::path::Path::new(&params.path),
            &re,
            &glob_matcher,
            recursive,
            include_dirs,
            max_results,
            show_size,
            show_modified,
            &mut entries,
            &mut file_count,
            &mut dir_count,
            &mut scanned_dirs,
            &mut total_size,
            &mut truncated_flag,
        )
        .map_err(|e| e_internal(e, None))?;

        let truncated = if truncated_flag {
            format!("\n... 结果已截断，最多显示 {} 条", max_results)
        } else {
            String::new()
        };

        // 紧凑输出
        let has_modified = show_modified && entries.iter().any(|(_, _, _, m)| !m.is_empty());
        let mut lines = Vec::new();
        for (path, is_dir, size, modified) in &entries {
            let mut parts = vec![
                if *is_dir { "d".to_string() } else { "f".to_string() },
                path.clone(),
            ];
            if show_size && !is_dir {
                parts.push(format!("{}B", size));
            }
            if has_modified && !modified.is_empty() {
                parts.push(modified.clone());
            }
            lines.push(parts.join(" "));
        }

        let total = if show_size { format!(" | {}B", total_size) } else { String::new() };
        Ok(format!(
            "{} | {}f {}d{} | {} dirs scanned{}",
            params.path, file_count, dir_count, total, scanned_dirs, truncated
        ) + if lines.is_empty() { String::new() } else { format!("\n{}", lines.join("\n")) }.as_str())
    }

    /// 获取文件元信息（大小、类型、修改时间、SHA256）
    #[tool(
        name = "file_info",
        description = "File/directory metadata: path | type | size | mtime (seconds) | sha256 | lines (text line count). sha256 is the same source as the read tools, so it can be used directly as expected_sha256",
        annotations(title = "Get file info", read_only_hint = true)
    )]
    fn file_info(
        &self,
        Parameters(params): Parameters<FileInfoParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let metadata = fs::metadata(&params.path).map_err(|e| {
            e_internal(format!("failed to get file info: {}", e), None)
        })?;

        let modified_str = metadata
            .modified()
            .ok()
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| format!("{}s", d.as_secs()))
                    .unwrap_or_else(|_| "-".to_string())
            })
            .unwrap_or_else(|| "-".to_string());

        let file_type = if metadata.is_file() {
            "文件"
        } else if metadata.is_dir() {
            "目录"
        } else {
            "其他"
        };

        // 版本指纹（与读取工具返回、写入前校验完全同一算法，可直接当 expected_sha256 用）
        let hash = if metadata.is_file() {
            Self::file_fingerprint(&params.path, metadata.len(), None)
                .map(|h| h[..16].to_string())
                .unwrap_or_else(|| "-".to_string())
        } else {
            "-".to_string()
        };

        // 文本文件额外回报行数：改完想确认"行数对不对 / 有没有被换行风格弄坏"时，
        // 用 file_info 就能核对，不必把整份内容再读进上下文（非文本/无法解码时显示 -）
        let lines = if metadata.is_file() {
            Self::count_lines_of(&params.path)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_string())
        } else {
            "-".to_string()
        };

        Ok(format!(
            "{} | {} | {}B | {} | sha256:{} | lines:{}",
            params.path, file_type, metadata.len(), modified_str, hash, lines
        ))
    }

    /// 删除文件(需用户确认)
    #[tool(
        name = "delete_file",
        description = "Delete a single file (directories not allowed). You must pass confirm=true explicitly to actually delete; when unconfirmed it returns E_INVALID_PARAM and echoes the file size and fingerprint; a backup is taken automatically before deletion, recoverable with manage_backups undo",
        annotations(title = "Delete file", destructive_hint = true)
    )]
    fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let path = std::path::Path::new(&params.path);

        // 与该文件的写操作互斥，避免"边写边删"（进程内锁 + 跨进程文件锁）
        let lock = self.lock_for(&params.path);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_guard = Self::acquire_file_lock(&params.path);

        if !path.exists() {
            return Err(e_param(format!("文件不存在: {}", params.path), None));
        }

        if !path.is_file() {
            return Ok(format!("路径不是普通文件，无法删除: {}", params.path));
        }

        // 删除不可逆：必须显式确认，未传 confirm=true 时只回报信息（含大小与指纹）供调用方判断
        if params.confirm != Some(true) {
            let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let fp = Self::file_fingerprint(&params.path, size, None)
                .map(|h| format!("sha256:{}", h))
                .unwrap_or_else(|| "sha256:不可用".to_string());
            return Err(e_param(
                format!(
                    "delete_file 需要显式确认：{} 将被删除（{}B，{}）。\
                     确认无误后请带 confirm=true 重新调用（删除前会自动备份，可用 manage_backups action=undo 恢复）",
                    params.path, size, fp
                ),
                None,
            ));
        }

        let size = fs::metadata(path)
            .map_err(|e| e_internal(format!("E_NOT_FOUND failed to get file info: {}", e), None))?
            .len();

        // 删除前备份（硬链接），删除后仍可用 manage_backups action=undo 恢复
        let bak = Self::backup_before_write(&params.path, "delete_file", None);
        retry_io(|| fs::remove_file(path)).map_err(|e| {
            e_internal(format!("E_WRITE 删除文件失败: {}", e), None)
        })?;
        let tail = if bak.is_some() { " | undoable" } else { "" };

        Ok(format!("OK {} | {}B deleted{}", params.path, size, tail))
    }

    /// 备份管理：列出 / 回滚 / 清理
    #[tool(
        name = "manage_backups",
        description = "Backup management (backups live in the tool's own directory, not polluting the project; up to 10 per file, auto-pruned beyond that). list = list / undo = roll back the most recent write or delete (rejected by default if the file changed again afterward, force=true overrides) / clean = clean up",
        annotations(title = "Backup management", destructive_hint = true)
    )]
    fn manage_backups(
        &self,
        Parameters(params): Parameters<ManageBackupsParams>,
    ) -> Result<String, McpError> {
        let params = {
            let mut p = params;
            p.path = self.resolve_path(&p.path)?;
            p
        };
        let action = params.action.to_lowercase();

        // list 是只读操作，不加锁，避免在目标目录创建/删除锁文件；
        // undo/clean 会改动文件或备份，才需要与写操作互斥。
        match action.as_str() {
            "list" => {
                let records = Self::list_backup_records(&params.path);
                if records.is_empty() {
                    return Ok(format!(
                        "{} | 0 backups | 备份目录: {}",
                        params.path,
                        Self::backup_dir_for(&params.path)
                            .map(|d| d.display().to_string())
                            .unwrap_or_else(|| "-".into())
                    ));
                }
                let mut lines = Vec::new();
                for (bak, meta) in &records {
                    let time = meta.get("time_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    let tool = meta.get("tool").and_then(|v| v.as_str()).unwrap_or("-");
                    let before = meta
                        .get("before_sha256")
                        .and_then(|v| v.as_str())
                        .map(|s| s.chars().take(16).collect::<String>())
                        .unwrap_or_else(|| "-".into());
                    let size = fs::metadata(bak).map(|m| m.len()).unwrap_or(0);
                    lines.push(format!(
                        "  {} | {} | {} | {}B | before:{}",
                        bak.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                        time,
                        tool,
                        size,
                        before
                    ));
                }
                Ok(format!(
                    "{} | {} backups | 最新在末尾\n{}",
                    params.path,
                    records.len(),
                    lines.join("\n")
                ))
            }
            "undo" => {
                // 会改文件，需与写操作互斥（进程内锁 + 跨进程文件锁）
                let lock = self.lock_for(&params.path);
                let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                let _file_guard = Self::acquire_file_lock(&params.path);
                let records = Self::list_backup_records(&params.path);
                let Some((bak, meta)) = records.last() else {
                    return Err(e_param(
                        format!("E_NOT_FOUND {} 没有任何备份可回滚", params.path),
                        None,
                    ));
                };
                let bak_bytes = fs::read(bak)
                    .map_err(|e| e_internal(format!("E_BACKUP 读取备份失败: {}", e), None))?;
                // 若文件在此之后又被改过，默认拒绝，避免把别人的新改动一起回滚掉
                let after_sha = meta.get("after_sha256").and_then(|v| v.as_str());
                if !params.force.unwrap_or(false) {
                    if let Some(after) = after_sha {
                        let cur = Self::path_fingerprint_short(&params.path);
                        // 文件已不存在（cur="-"）时允许回滚恢复；否则要求当前内容与备份记录的"写入后内容"一致
                        if cur != "-" && !after.eq_ignore_ascii_case(&cur) {
                            return Err(e_param(
                                format!(
                                    "E_EXTERNAL_CHANGED 文件在备份之后又被修改过，拒绝回滚以免丢失新改动。\n\
                                     文件: {}\n备份对应的写入后 sha256: {}\n当前 sha256: {}\n\
                                     确认要丢弃这些改动请用 force=true 重试",
                                    params.path, after, cur
                                ),
                                None,
                            ));
                        }
                    }
                }
                // 回滚前把当前内容也备份一份，这样"回滚"本身也能被撤销
                let current_bak = if std::path::Path::new(&params.path).exists() {
                    Self::backup_before_write(&params.path, "undo(回滚前快照)", None)
                } else {
                    if let Some(dir) = Self::backup_dir_for(&params.path) {
                        let _ = retry_io(|| fs::create_dir_all(&dir));
                    }
                    None
                };
                Self::atomic_write_ex(
                    &params.path,
                    &bak_bytes,
                    current_bak.as_ref().map(|b| b.bak.as_path()),
                )
                .map_err(|e| {
                    e_internal(format!("E_WRITE 回滚写入失败: {}", e), None)
                })?;
                if let Some(h) = &current_bak {
                    Self::finish_backup(h, &bak_bytes);
                }
                // 已消费的备份移出列表（连同 meta），避免重复回滚同一版本
                let _ = fs::remove_file(bak);
                let _ = fs::remove_file(bak.with_extension("json"));
                let tool = meta.get("tool").and_then(|v| v.as_str()).unwrap_or("-");
                Ok(format!(
                    "OK {} | 已回滚到 {} 之前的版本（该备份由 {} 创建） | {}B | sha256:{}",
                    params.path,
                    bak.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                    tool,
                    bak_bytes.len(),
                    Self::fingerprint_short_of_bytes(&bak_bytes)
                ))
            }
            "clean" => {
                // 会删备份，需与写操作互斥（进程内锁 + 跨进程文件锁）
                let lock = self.lock_for(&params.path);
                let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                let _file_guard = Self::acquire_file_lock(&params.path);
                let keep = params.keep.unwrap_or(BACKUP_KEEP);
                let Some(dir) = Self::backup_dir_for(&params.path) else {
                    return Ok(format!("{} | 备份目录无效", params.path));
                };
                let before = Self::list_backup_records(&params.path).len();
                Self::trim_backups(&dir, keep);
                let after = Self::list_backup_records(&params.path).len();
                Ok(format!(
                    "OK {} | 清理完成 | {} → {} 份备份 | keep={}",
                    params.path, before, after, keep
                ))
            }
            _ => Err(e_param(
                format!(
                    "E_INVALID_PARAM 不支持的 action: {}，可选: list, undo, clean",
                    params.action
                ),
                None,
            )),
        }
    }



    /// 复制文件
    #[tool(
        name = "copy_files",
        description = "Copy files (auto-creates directories): with multiple sources target is treated as a directory; with a single source you may specify a new path/name; existing targets are skipped by default, overwrite=true overrides",
        annotations(title = "Copy files", destructive_hint = true)
    )]
    fn copy_files(
        &self,
        Parameters(params): Parameters<CopyFilesParams>,
    ) -> Result<String, McpError> {
        let overwrite = params.overwrite.unwrap_or(false);
        let target = self.resolve_path(&params.target)?;
        let target_path = std::path::Path::new(&target);

        // 解析所有源文件路径
        let sources: Vec<String> = params.sources.iter()
            .map(|s| self.resolve_path(s))
            .collect::<Result<Vec<_>, _>>()?;

        // 目标语义：已存在按实际类型；不存在时多文件=目录、单文件=新文件路径（除非路径以分隔符结尾）
        let target_is_dir = Self::target_is_dir_for(target_path, &params.target, sources.len());

        // 校验所有源文件存在
        for s in &sources {
            if !std::path::Path::new(s).is_file() {
                return Err(e_param(
                    format!("源文件不存在或不是普通文件: {}", s), None,
                ));
            }
        }

        // 如果是多文件，目标必须是目录
        if sources.len() > 1 && target_path.exists() && !target_is_dir {
            return Err(e_param(
                format!("多文件复制时目标必须是目录: {}", target), None,
            ));
        }

        // 确保目标目录存在
        if target_is_dir {
            retry_io(|| fs::create_dir_all(target_path))
                .map_err(|e| e_internal(format!("创建目标目录失败: {}", e), None))?;
        } else {
            // 单文件且目标不是目录，确保父目录存在
            if let Some(parent) = target_path.parent() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| e_internal(format!("创建父目录失败: {}", e), None))?;
            }
        }

        let mut copied = 0u64;
        let mut skipped = 0u64;
        let mut results = Vec::new();

        for src in &sources {
            let src_path = std::path::Path::new(src);
            let file_name = src_path.file_name().ok_or_else(|| {
                e_param(format!("无法获取文件名: {}", src), None)
            })?;

            let dest = if target_is_dir {
                target_path.join(file_name)
            } else {
                target_path.to_path_buf()
            };

            let dest_str = dest.to_string_lossy().to_string();
            // 源与目标相同（复制到自身）：直接跳过，否则 overwrite=true 时 fs::copy 会报"文件被占用"
            if src.as_str() == dest_str {
                results.push(format!("跳过 {} (源与目标相同)", dest.display()));
                skipped += 1;
                continue;
            }

            if dest.exists() && !overwrite {
                results.push(format!("跳过 {} (已存在)", dest.display()));
                skipped += 1;
                continue;
            }

            let size = fs::metadata(src)
                .map_err(|e| e_internal(format!("无法读取源文件信息: {}", e), None))?
                .len();

            // 与目标文件的其他写操作互斥（进程内锁 + 跨进程文件锁）
            let lock = self.lock_for(&dest_str);
            let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let _file_guard = Self::acquire_file_lock(&dest_str);
            retry_io(|| fs::copy(src, &dest))
                .map_err(|e| e_internal(format!("复制失败 {} -> {}: {}", src, dest.display(), e), None))?;

            copied += size;
            results.push(format!("OK {} -> {} | {}B", src, dest.display(), size));
        }

        Ok(format!(
            "{} | {} copied, {} skipped | {}B copied\n{}",
            if target_is_dir { target.to_string() } else { target_path.to_string_lossy().to_string() },
            results.len() as u64 - skipped,
            skipped,
            copied,
            results.join("\n"),
        ))
    }

    /// 移动/重命名文件
    #[tool(
        name = "move_files",
        description = "Move/rename files (auto-creates directories): with multiple sources target is treated as a directory; with a single source you may specify a new path/name; existing targets are skipped by default, overwrite=true overrides",
        annotations(title = "Move files", destructive_hint = true)
    )]
    fn move_files(
        &self,
        Parameters(params): Parameters<MoveFilesParams>,
    ) -> Result<String, McpError> {
        let overwrite = params.overwrite.unwrap_or(false);
        let target = self.resolve_path(&params.target)?;
        let target_path = std::path::Path::new(&target);

        // 解析所有源文件路径
        let sources: Vec<String> = params.sources.iter()
            .map(|s| self.resolve_path(s))
            .collect::<Result<Vec<_>, _>>()?;

        // 目标语义：已存在按实际类型；不存在时多文件=目录、单文件=新文件路径（除非路径以分隔符结尾）
        let target_is_dir = Self::target_is_dir_for(target_path, &params.target, sources.len());

        // 校验所有源文件存在
        for s in &sources {
            if !std::path::Path::new(s).is_file() {
                return Err(e_param(
                    format!("源文件不存在或不是普通文件: {}", s), None,
                ));
            }
        }

        // 如果是多文件，目标必须是目录
        if sources.len() > 1 && target_path.exists() && !target_is_dir {
            return Err(e_param(
                format!("多文件移动时目标必须是目录: {}", target), None,
            ));
        }

        // 确保目标目录存在
        if target_is_dir {
            retry_io(|| fs::create_dir_all(target_path))
                .map_err(|e| e_internal(format!("创建目标目录失败: {}", e), None))?;
        } else {
            if let Some(parent) = target_path.parent() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| e_internal(format!("创建父目录失败: {}", e), None))?;
            }
        }

        let mut moved = 0u64;
        let mut skipped = 0u64;
        let mut results = Vec::new();

        for src in &sources {
            let src_path = std::path::Path::new(src);
            let file_name = src_path.file_name().ok_or_else(|| {
                e_param(format!("无法获取文件名: {}", src), None)
            })?;

            let dest = if target_is_dir {
                target_path.join(file_name)
            } else {
                target_path.to_path_buf()
            };

            if dest.exists() && !overwrite {
                results.push(format!("跳过 {} (已存在)", dest.display()));
                skipped += 1;
                continue;
            }

            let size = fs::metadata(src)
                .map_err(|e| e_internal(format!("无法读取源文件信息: {}", e), None))?
                .len();

            let dest_str = dest.to_string_lossy().to_string();
            // 源与目标相同（重命名到自身）：无需操作
            if src.as_str() == dest_str {
                results.push(format!("跳过 {} (源与目标相同)", dest.display()));
                skipped += 1;
                continue;
            }
            // 固定顺序加锁（进程内 + 跨进程文件锁），避免并发 A→B / B→A 时互相等待死锁
            let src_first = src.as_str() < dest_str.as_str();
            let (p1, p2) = if src_first {
                (src.as_str(), dest_str.as_str())
            } else {
                (dest_str.as_str(), src.as_str())
            };
            let l1 = self.lock_for(p1);
            let _g1 = l1.lock().unwrap_or_else(|e| e.into_inner());
            let l2 = self.lock_for(p2);
            let _g2 = l2.lock().unwrap_or_else(|e| e.into_inner());
            let _f1 = Self::acquire_file_lock(p1);
            let _f2 = Self::acquire_file_lock(p2);
            // 跨卷时 rename 会失败（Windows ERROR_NOT_SAME_DEVICE=17 / Unix EXDEV=18），回退为"复制 + 删除"
            match retry_io(|| fs::rename(src, &dest)) {
                Ok(()) => {}
                Err(e) if Self::is_cross_device_error(&e) => {
                    retry_io(|| fs::copy(src, &dest)).map_err(|e| {
                        e_internal(format!("跨卷移动复制失败 {} -> {}: {}", src, dest.display(), e), None)
                    })?;
                    retry_io(|| fs::remove_file(src)).map_err(|e| {
                        e_internal(format!("跨卷移动删除源文件失败 {}: {}", src, e), None)
                    })?;
                }
                Err(e) => {
                    return Err(e_internal(format!("移动失败 {} -> {}: {}", src, dest.display(), e), None));
                }
            }

            moved += size;
            results.push(format!("OK {} -> {} | {}B", src, dest.display(), size));
        }

        Ok(format!(
            "{} | {} moved, {} skipped | {}B moved\n{}",
            if target_is_dir { target.to_string() } else { target_path.to_string_lossy().to_string() },
            results.len() as u64 - skipped,
            skipped,
            moved,
            results.join("\n"),
        ))
    }

    /// 按行编辑文件：删除/插入/替换/追加行
    #[tool(
        name = "edit_file_lines",
        description = "Edit by line (1-based): delete_lines/insert_lines/replace_lines/append_lines. Locate with anchor_text (whole line, must be unique) or anchor_regex, or directly give start_line/end_line; delete/replace require expected_old for a second check; dry_run=true returns only a diff. \
Also supports a \"context block\" mode: give context_before + context_after (mutually exclusive with expected_old/anchor/line-number, and expected_sha256 is required); the tool auto-locates the (implied) text between the two frames and replaces it with content; two adjacent frames mean inserting content between them — the AI need not repeat large chunks of old text.",
        annotations(title = "Edit file by line", destructive_hint = true)
    )]
    fn edit_file_lines(
        &self,
        Parameters(params): Parameters<EditFileLinesParams>,
    ) -> Result<String, McpError> {
        let target = params.path.or(params.file_path).ok_or_else(|| {
            e_param("缺少 path 或 file_path 参数", None)
        })?;
        let target = self.resolve_path(&target)?;

        // 上下文块模式（强版）参数校验：与 expected_old/锚点/行号 互斥，且必须传 expected_sha256
        let context_active = params.context_before.is_some() || params.context_after.is_some();
        if params.context_before.is_some() != params.context_after.is_some() {
            return Err(e_param(
                "context_before 与 context_after 必须同时提供或同时省略",
                None,
            ));
        }
        if context_active {
            if params.expected_old.is_some()
                || params.anchor_text.is_some()
                || params.anchor_regex.is_some()
                || params.start_line.is_some()
                || params.end_line.is_some()
                || params.anchor_occurrence.is_some()
            {
                return Err(e_param(
                    "使用上下文块(context_before/context_after)时，不能再提供 expected_old/anchor_text/anchor_regex/start_line/end_line/anchor_occurrence（互斥）",
                    None,
                ));
            }
            match params.expected_sha256.as_deref() {
                Some(s) if s.trim().len() >= 8 => {}
                _ => {
                    return Err(e_param(
                        "E_INVALID_PARAM 使用上下文块时必须传 expected_sha256（文件级并发防护兜底，防止读-写之间文件被他人改动）",
                        None,
                    ));
                }
            }
        }

        // 同一文件的读-改-写串行化：多个 AI 并发编辑同一文件时不会互相覆盖
        self.with_path_lock(&target, || {
        // 读取文件字节
        let bytes = retry_io(|| fs::read(&target)).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    e_internal(format!("文件不存在: {}", target), None)
                }
                std::io::ErrorKind::PermissionDenied => {
                    e_internal(format!("没有权限操作文件: {}", target), None)
                }
                _ => e_internal(format!("failed to read file: {}", e), None),
            }
        })?;

        // 写前版本校验：文件已被其他 AI/程序改过则拒绝，避免整文件写回时抹掉别人的修改
        Self::check_expected_sha(&target, &bytes, params.expected_sha256.as_deref())?;

        // 决定编辑编码：默认保持原文件编码；指定编码与实际不一致时直接报错返回真实编码
        let encoding_name = Self::resolve_write_encoding(&target, params.encoding.as_deref(), Some(&bytes))?;

        // 统一解码：剥离 BOM 并记录 BOM/编码/主换行风格，写回时原样复原
        let ft = Self::decode_file(&bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?;
        // 解码时替换过非法字节的内容不允许写回，否则原字节被永久破坏
        if ft.has_invalid {
            return Err(e_internal(
                format!(
                    "文件 {} 按 {} 解码时存在非法字节（已用 U+FFFD 替换），拒绝写回以免原字节永久丢失。\
                     请确认文件真实编码后用正确的 encoding 重新调用",
                    target, ft.encoding
                ),
                None,
            ));
        }
        let line_ending = ft.line_ending;
        let encoding_label = Self::encoding_label(&ft);
        let bom = ft.bom;
        let encoding = ft.encoding.clone();

        // 拆分为"裸行"（去掉行尾 \r），写回时统一用主换行风格 line_ending 连接，
        // 保证一个文件不会残留多种换行符。
        // 空文件按 0 行处理：否则 append_lines 会在文件开头插出一个空行
        let lines: Vec<String> = if ft.content.is_empty() {
            Vec::new()
        } else {
            ft.content
                .split('\n')
                .map(|s| s.trim_end_matches('\r').to_string())
                .collect()
        };
        let total_lines = lines.len();
        let mut modified: Vec<String> = lines.clone();

        // 上下文块模式（强版）：把 (before, after) 两帧解析成 (start, end, operation, expected_old)，
        // 之后复用下方既有的 anchor/operation 逻辑；非上下文模式则原样回退到 params。
        // 这样 AI 只需给"改动点两侧的小段上下文"，工具自己算出被隐含的旧文本并做精确校验，无需复述大段旧内容。
        let (eff_start, eff_end, eff_op, eff_old): (
            Option<usize>,
            Option<usize>,
            String,
            Option<String>,
        ) = if context_active {
            let cb_before = params.context_before.as_deref().unwrap().trim_end_matches(['\r', '\n']);
            let cb_after = params.context_after.as_deref().unwrap().trim_end_matches(['\r', '\n']);
            let before_lines: Vec<String> = cb_before
                .split('\n')
                .map(|s| s.trim_end_matches('\r').to_string())
                .collect();
            let after_lines: Vec<String> = cb_after
                .split('\n')
                .map(|s| s.trim_end_matches('\r').to_string())
                .collect();
            if before_lines.is_empty() || after_lines.is_empty() {
                return Err(e_param(
                    "context_before/context_after 不能为空（各需至少一行真实文本）",
                    None,
                ));
            }
            let kb = before_lines.len();
            let ka = after_lines.len();
            if kb > total_lines || ka > total_lines {
                return Err(e_param(
                    format!(
                        "context_before({}行)/context_after({}行) 超过文件总行数({})",
                        kb, ka, total_lines
                    ),
                    None,
                ));
            }
            // 找出 before/after 各自的精确命中起点
            let before_hits: Vec<usize> = (0..=(total_lines - kb))
                .filter(|&b| lines[b..b + kb] == before_lines[..])
                .collect();
            let after_hits: Vec<usize> = (0..=(total_lines - ka))
                .filter(|&a| lines[a..a + ka] == after_lines[..])
                .collect();
            // 候选落点：before 在前、after 在后（after 起点 >= before 块尾）
            let mut cands: Vec<(usize, usize)> = Vec::new();
            for &b in &before_hits {
                for &a in &after_hits {
                    if a >= b + kb {
                        cands.push((b, a));
                    }
                }
            }
            match cands.len() {
                0 => {
                    return Err(e_param(
                        format!(
                            "E_NOT_FOUND 上下文块未匹配到唯一落点：context_before 命中 {} 处、context_after 命中 {} 处，但不存在 before 在前 after 在后的组合。请确认两者是文件中真实的连续片段",
                            before_hits.len(),
                            after_hits.len()
                        ),
                        None,
                    ));
                }
                1 => {
                    let (b, a) = cands[0];
                    let gap_start = b + kb; // 0-based：被隐含替换/插入区间的起点
                    let gap_end = a; // 0-based：区间终点（不含）
                    if gap_start == gap_end {
                        // 两帧相邻 → 在其间插入 content
                        (Some(gap_start + 1), Some(gap_start), "insert_lines".to_string(), None)
                    } else {
                        // 两帧之间夹着旧文本 → 用 content 替换它（expected_old 由工具推导并精确校验）
                        let old = lines[gap_start..gap_end].join("\n");
                        (Some(gap_start + 1), Some(gap_end), "replace_lines".to_string(), Some(old))
                    }
                }
                _ => {
                    let list: Vec<String> = cands
                        .iter()
                        .map(|(b, a)| {
                            let gs = b + kb;
                            if gs == *a {
                                format!("第 {} 行后插入", gs + 1)
                            } else {
                                format!("第 {}~{} 行", gs + 1, a)
                            }
                        })
                        .collect();
                    return Err(e_param(
                        format!(
                            "E_NOT_UNIQUE 上下文块落点不唯一（命中 {} 处）。请用更长的 context_before/context_after 缩小范围，或改用锚点/行号定位。候选区间(改动前,1-based): {}",
                            cands.len(),
                            list.join("; ")
                        ),
                        None,
                    ));
                }
            }
        } else {
            (
                params.start_line,
                params.end_line,
                params.operation.clone(),
                params.expected_old.clone(),
            )
        };

        // 辅助：对期望旧内容进行比对（用于防止行号算错）
        let check_expected_old = |range: std::ops::Range<usize>, expected: &str| -> Result<(), McpError> {
            let actual_lines: Vec<String> = lines[range.clone()]
                .iter()
                .map(|s| s.trim_end_matches('\r').to_string())
                .collect();
            // 逐行比较，兼容 \r\n
            // 容忍 expected_old 尾随的单个换行（AI 常把整行连同换行一起复制过来）：
            // 否则 split 会多出一个空元素导致长度不等而误拒。
            let expected = expected
                .strip_suffix("\r\n")
                .or_else(|| expected.strip_suffix('\n'))
                .unwrap_or(expected);
            let expected_lines: Vec<&str> = expected.split('\n').collect();
            let matches = expected_lines.len() == actual_lines.len()
                && expected_lines.iter().zip(actual_lines.iter()).all(|(e, a)| e.trim_end_matches('\r') == a.as_str());
            if !matches {
                // 输出实际内容 (附近 ±2 行上下文)
                let ctx_start = (range.start.saturating_sub(2)).max(0);
                let ctx_end = (range.end + 2).min(total_lines);
                let width = total_lines.to_string().len().max(3);
                let mut ctx = String::new();
                for i in ctx_start..ctx_end {
                    let mark = if i >= range.start && i < range.end { ">>>" } else { "   " };
                    ctx.push_str(&format!(
                        "{} {:>width$}| {}\n",
                        mark,
                        i + 1,
                        lines[i].trim_end_matches('\r'),
                        width = width
                    ));
                }
                // 行数不符是"行号算错"最常见的成因，直接点明，省掉一轮试错往返
                let count_hint = if expected_lines.len() == actual_lines.len() {
                    String::new()
                } else {
                    format!(
                        "⚠️ 行数不符：声明的区间 {}~{} 只覆盖 {} 行，而 expected_old 是 {} 行（{} {} 行）。\
                         请核对 start_line/end_line，或让 expected_old 的行数与区间完全一致。\n",
                        range.start + 1,
                        range.end,
                        actual_lines.len(),
                        expected_lines.len(),
                        if expected_lines.len() > actual_lines.len() { "多" } else { "少" },
                        (expected_lines.len() as isize - actual_lines.len() as isize).abs()
                    )
                };
                return Err(e_param(
                    format!(
                        "expected_old 不匹配！行号可能算错了。期望 {}~{} 行的实际内容与提供的 expected_old 不一致。\n\
                         {}\
                         文件总行数: {}\n\
                         === 期望内容({}行):\n{}\n\
                         === 实际内容(上下文 >>> 标记目标行):\n{}",
                        range.start + 1,
                        range.end,
                        count_hint,
                        total_lines,
                        expected_lines.len(),
                        expected,
                        ctx
                    ),
                    None,
                ));
            }
            Ok(())
        };

        // 锚点定位：把 anchor_text / anchor_regex 换算成行号（默认要求全文唯一命中，避免改错位置）
        let used_anchor = params.anchor_text.is_some() || params.anchor_regex.is_some();
        if params.anchor_text.is_some() && params.anchor_regex.is_some() {
            return Err(e_param(
                "anchor_text 与 anchor_regex 不能同时使用，请二选一",
                None,
            ));
        }
        let mut start_line = eff_start;
        let mut end_line = eff_end;
        if used_anchor {
            if params.start_line.is_some() {
                return Err(e_param(
                    "anchor_text/anchor_regex 与 start_line 不能同时使用，请二选一",
                    None,
                ));
            }
            let hits: Vec<usize> = if let Some(t) = &params.anchor_text {
                let t = t.trim_end_matches('\r');
                lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.trim_end_matches('\r') == t)
                    .map(|(i, _)| i + 1)
                    .collect()
            } else {
                let pat = params.anchor_regex.as_deref().unwrap_or("");
                let re = Regex::new(pat).map_err(|e| {
                    e_param(format!("anchor_regex 正则表达式错误: {}", e), None)
                })?;
                lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| re.is_match(l))
                    .map(|(i, _)| i + 1)
                    .collect()
            };
            match hits.len() {
                0 => {
                    // 未精确命中时给出"含该文本的行"作为提示，省掉一轮重新读取
                    let mut hints: Vec<String> = Vec::new();
                    if let Some(t) = params.anchor_text.as_deref().map(|s| s.trim()) {
                        if !t.is_empty() {
                            for (i, l) in lines.iter().enumerate() {
                                let l = l.trim_end_matches('\r');
                                if l.contains(t) {
                                    hints.push(format!("第 {} 行: {}", i + 1, l.trim()));
                                    if hints.len() >= 5 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let hint = if hints.is_empty() {
                        String::new()
                    } else {
                        format!("\n可能想改的行（包含你给的文本）:\n  {}", hints.join("\n  "))
                    };
                    return Err(e_param(
                        format!(
                            "E_NOT_FOUND 锚点未精确匹配到任何行（anchor_text={:?} anchor_regex={:?}）。\
                             注意 anchor_text 需与整行完整一致（含缩进）；确认真实内容可先 read_text_lines{}",
                            params.anchor_text, params.anchor_regex, hint
                        ),
                        None,
                    ));
                }
                1 => start_line = Some(hits[0]),
                n => match params.anchor_occurrence {
                    Some(occ) if occ >= 1 && occ <= n => start_line = Some(hits[occ - 1]),
                    Some(occ) => {
                        return Err(e_param(
                            format!("anchor_occurrence={} 超出命中数量 {}", occ, n),
                            None,
                        ));
                    }
                    None => {
                        let list = hits
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        return Err(e_param(
                            format!(
                                "E_NOT_UNIQUE 锚点命中 {} 处（行: {}），无法确定要改哪一处。\
                                 请把 anchor_text 写得更完整（含上下文/缩进），或指定 anchor_occurrence 选择第几处",
                                n, list
                            ),
                            None,
                        ));
                    }
                },
            }
            // 锚点默认只作用于命中那一行；显式给了更大的 end_line 时按范围处理
            if end_line.unwrap_or(0) < start_line.unwrap_or(1) {
                end_line = start_line;
            }
        }

        let result = match eff_op.as_str() {
            "delete_lines" => {
                let start = start_line.ok_or_else(|| {
                    e_param("删除行操作需要指定 start_line 或 anchor_text/anchor_regex", None)
                })?;
                // 锚点模式下 end_line 可省（默认只删命中那一行）；否则必须显式给出范围
                let end = end_line
                    .or(if used_anchor { Some(start) } else { None })
                    .ok_or_else(|| e_param("删除行操作需要指定 end_line", None))?;
                if start < 1 || end > total_lines || start > end {
                    return Err(e_param(
                        format!("invalid line range: {}-{}, total lines: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = eff_old.as_deref().ok_or_else(|| {
                    e_param(
                        "delete_lines 必须提供 expected_old（将 read_text_lines 读到的目标行原样传入），用于防止行号算错",
                        None,
                    )
                })?;
                check_expected_old((start - 1)..end, exp)?;
                modified.drain(start - 1..end);
                format!("del {}~{}", start, end)
            }

            "insert_lines" => {
                let start = start_line.ok_or_else(|| {
                    e_param("插入行操作需要指定 start_line 或 anchor_text/anchor_regex", None)
                })?;
                let insert_content = params.content.as_ref().ok_or_else(|| {
                    e_param("insert_lines requires content", None)
                })?;
                if start < 1 || start > total_lines + 1 {
                    return Err(e_param(
                        format!("invalid insert position: {}, total lines: {}", start, total_lines),
                        None,
                    ));
                }
                // 拆分插入内容，兼容 \r\n
                let insert_lines: Vec<String> = insert_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                let idx = start - 1;
                // 插入点在文件末尾且文件以换行结尾时，split 产生的末尾空串只是"结尾换行标记"，
                // 应插到它之前，否则会凭空多出一个空行（与 append_lines 保持一致）
                let idx = if idx == modified.len()
                    && modified.last().map(|s| s.is_empty()).unwrap_or(false)
                {
                    idx - 1
                } else {
                    idx
                };
                let mut new = Vec::with_capacity(total_lines + insert_lines.len());
                new.extend(modified.drain(..idx));
                new.extend(insert_lines);
                new.extend(modified);
                modified = new;
                format!("ins @{}", start)
            }

            "replace_lines" => {
                let start = start_line.ok_or_else(|| {
                    e_param("replace_lines requires start_line or anchor_text/anchor_regex", None)
                })?;
                let end = end_line.unwrap_or(start);
                if end < start {
                    return Err(e_param(
                        format!("invalid line range: {}-{}", start, end),
                        None,
                    ));
                }
                let replace_content = params.content.as_ref().ok_or_else(|| {
                    e_param("replace_lines requires content", None)
                })?;
                if start < 1 || end > total_lines || start > end {
                    return Err(e_param(
                        format!("invalid line range: {}-{}, total lines: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = eff_old.as_deref().ok_or_else(|| {
                    e_param(
                        "replace_lines requires expected_old (pass the target lines exactly as read by read_text_lines) to prevent miscounted line numbers",
                        None,
                    )
                })?;
                check_expected_old((start - 1)..end, exp)?;
                let replace_lines: Vec<String> = replace_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                modified.splice(start - 1..end, replace_lines);
                format!("repl {}~{}", start, end)
            }

            "append_lines" => {
                let append_content = params.content.as_ref().ok_or_else(|| {
                    e_param("append_lines requires content", None)
                })?;
                let append_lines: Vec<String> = append_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                // 文件以换行结尾时，split 产生的末尾空串只是"结尾换行标记"而不是真实空行：
                // 追加应插在它之前，否则会凭空多出一个空行（"a\nb\n" + "c" 会变成 "a\nb\n\nc"）。
                let insert_at = if modified.last().map(|s| s.is_empty()).unwrap_or(false) {
                    modified.len() - 1
                } else {
                    modified.len()
                };
                let mut new_lines = Vec::with_capacity(modified.len() + append_lines.len());
                new_lines.extend(modified.drain(..insert_at));
                new_lines.extend(append_lines);
                new_lines.extend(modified);
                modified = new_lines;
                format!("append")
            }

            _ => {
                return Err(e_param(
                    format!(
                        "unsupported operation: {}, choose from: delete_lines, insert_lines, replace_lines, append_lines",
                        params.operation
                    ),
                    None,
                ));
            }
        };

        // 用主换行风格统一连接，保证写回后整个文件只有一种换行符
        let new_content = modified.join(line_ending);
        let new_bytes = Self::encode_file(&FileText {
            encoding: encoding.clone(),
            bom,
            line_ending,
            content: new_content.clone(),
            has_invalid: false,
        })
        .map_err(|e| e_internal(e, None))?;

        // dry-run：只返回 diff 预览，不写文件、不备份
        if params.dry_run.unwrap_or(false) {
            return Ok(format!(
                "DRY-RUN | {} | {} | {} | {}→{} lines | {}B→{}B | not written\n{}expected sha256:{}\nremove dry_run and retry to write",
                target,
                encoding_label,
                result,
                total_lines,
                modified.len(),
                bytes.len(),
                new_bytes.len(),
                Self::unified_diff(&ft.content, &new_content, 200),
                Self::fingerprint_short_of_bytes(&new_bytes)
            ));
        }

        // 自动创建父目录
        Self::ensure_parent_dir(&target)
            .map_err(|e| e_internal(e, None))?;

        // 写前备份（硬链接零拷贝），便于事后回滚
        let bak = Self::backup_before_write(&target, "edit_file_lines", Some(&bytes));
        // 原子写入：先写临时文件再 rename 替换，中途失败不会损坏原文件
        Self::atomic_write_ex(&target, &new_bytes, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                e_internal(format!("E_NO_PERMISSION no permission to operate on file: {}", target), None)
            } else {
                e_internal(format!("E_WRITE write file failed: {}", e), None)
            }
        })?;
        let mut tail = String::new();
        if let Some(h) = &bak {
            Self::finish_backup(h, &new_bytes);
            tail = " | undoable".to_string();
        }

        Ok(format!(
            "{} | {} | {} | {}→{} lines | {}B | sha256:{}{}",
            result,
            target,
            encoding_label,
            total_lines,
            modified.len(),
            new_bytes.len(),
            Self::fingerprint_short_of_bytes(&new_bytes),
            tail
        ))
        })
    }

    /// 多文件只读预览：把多个 edit_file_lines 式改动（支持锚点/行号/上下文块）聚合成一份紧凑 diff，
    /// 不写入、不备份。确认无误后再逐文件调用对应编辑工具实写。
    #[tool(
        name = "preview_edits",
        description = "Read-only multi-file preview: aggregates several edit_file_lines-style changes (anchors/line numbers/context blocks) into one compact diff, without writing or backing up. After confirming, call the per-file edit tool to actually apply. edits=[{path, operation?, content?, expected_old?, anchor_*, start_line?, end_line?, context_before?, context_after?, expected_sha256?}]",
        annotations(title = "Multi-file edit preview", read_only_hint = true)
    )]
    fn preview_edits(
        &self,
        Parameters(params): Parameters<PreviewEditsParams>,
    ) -> Result<String, McpError> {
        if params.edits.is_empty() {
            return Err(e_param("edits must not be empty: provide at least one edit description", None));
        }
        let mut out = String::new();
        let mut ok = 0usize;
        let mut failed = 0usize;
        for (i, spec) in params.edits.iter().enumerate() {
            let edit_params = EditFileLinesParams {
                operation: spec
                    .operation
                    .clone()
                    .unwrap_or_else(|| "replace_lines".to_string()),
                path: Some(spec.path.clone()),
                file_path: None,
                start_line: spec.start_line,
                end_line: spec.end_line,
                content: spec.content.clone(),
                encoding: spec.encoding.clone().or(params.encoding.clone()),
                expected_old: spec.expected_old.clone(),
                expected_sha256: spec.expected_sha256.clone(),
                anchor_text: spec.anchor_text.clone(),
                anchor_regex: spec.anchor_regex.clone(),
                anchor_occurrence: spec.anchor_occurrence,
                dry_run: Some(true),
                context_before: spec.context_before.clone(),
                context_after: spec.context_after.clone(),
            };
            out.push_str(&format!("\n──── file {}: {} ────\n", i + 1, spec.path));
            match self.edit_file_lines(Parameters(edit_params)) {
                Ok(diff) => {
                    ok += 1;
                    out.push_str(&diff);
                    out.push('\n');
                }
                Err(e) => {
                    failed += 1;
                    out.push_str(&format!("❌ preview failed: {}\n", e));
                }
            }
        }
        out.push_str(&format!(
            "\n=== summary: {} succeeded, {} failed (preview only, no file written) ===\n",
            ok, failed
        ));
        Ok(out)
    }
}

/// 最近一次 panic 的文本：由启动时装的 hook 写入、catch_unwind 分支取走。
/// 只有"两个工具同时 panic"这种极罕见并发下才可能串味，不影响兜底本身。
static LAST_PANIC_MSG: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

/// 装 panic hook：① 截获 panic 文本供兜底分支回显；② 保留默认 stderr 输出——
/// 默认输出里的 `文件:行号` 是定位依据（release 虽 strip 掉符号表，这行仍在），不能吃掉。
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload_as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| "unknown panic (payload is not a string)".to_string());
        if let Ok(mut slot) = LAST_PANIC_MSG
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
        {
            *slot = Some(msg);
        }
        default(info);
    }));
}

/// 包住 ToolRouter：把工具实现里的 panic 兜住，降级成一条普通错误返回。
///
/// 背景：edit_file_sections 曾在"中文 + start_line"的分支上数组越界 panic，
/// 而 release 配了 `panic = "abort"`，一次 panic 就把整个 MCP 服务带走——
/// stdio 下调用方只看到超时/断连，HTTP 下整个进程退出、所有会话一起没。
/// 这里在派发处加一层 catch_unwind：某个工具崩了只影响这一次调用，
/// 服务继续运行、其余工具照常可用。
///
/// 覆盖不到的是"工具之外"的 panic（rmcp 协议层、传输层），那仍会让进程退出；
/// 但绝大多数风险在本文件这几千行手写的下标/切片逻辑里，已被这里兜住。
struct PanicSafeRouter<'a> {
    inner: &'a rmcp::handler::server::router::tool::ToolRouter<FileIoServer>,
}

impl<'a> PanicSafeRouter<'a> {
    async fn call(
        self,
        tcc: rmcp::handler::server::tool::ToolCallContext<'_, FileIoServer>,
    ) -> Result<rmcp::model::CallToolResult, McpError> {
        let tool_name = tcc.name().to_string();
        let fut = self.inner.call(tcc);
        // AssertUnwindSafe：future 里持有 &self/&params 的共享引用，编译器无法证明
        // UnwindSafe。panic 后我们立刻丢弃这个 future（不再 poll），不会观察到中间态。
        match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(fut)).await {
            Ok(result) => result,
            Err(payload) => {
                let msg = Self::panic_message(&payload);
                // 打一条 stderr：release 虽 strip 掉符号表，但 panic 的 文件:行号 仍在，便于定位
                eprintln!(
                    "[file-io-mcp] tool {} panicked internally (captured, server continues): {}",
                    tool_name, msg
                );
                Err(e_internal(
                    format!(
                        "E_PANIC internal error in tool {}, captured -- server continues, you may call other tools: {}.\
                         This is an implementation defect; please report this message together with the current input",
                        tool_name, msg
                    ),
                    None,
                ))
            }
        }
    }

    fn list_all(&self) -> Vec<rmcp::model::Tool> {
        self.inner.list_all()
    }

    /// 返回值按 'a 而不是跟随 &self：调用方写法是 `self.safe_router().get(name)`，
    /// 跟 &self 的话会在临时值上借用、语句结束即失效。
    fn get(&self, name: &str) -> Option<&'a rmcp::model::Tool> {
        self.inner.get(name)
    }

    /// 取走最近一次 panic 的文本（由启动时装的 hook 写入），取完即清空
    fn take_last_panic_msg() -> Option<String> {
        LAST_PANIC_MSG.get()?.lock().ok().and_then(|mut g| g.take())
    }

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        // rustc 1.98 起 panic!("...") 的 payload 是 std 的内部类型，实测 downcast 到
        // &str / String 都是 None；但 PanicHookInfo::payload_as_str() 能取到文本，
        // 故优先用 hook 截获的内容，downcast 仅作兜底。
        if let Some(msg) = Self::take_last_panic_msg() {
            return msg;
        }
        if let Some(s) = payload.downcast_ref::<&str>() {
            return (*s).to_string();
        }
        if let Some(s) = payload.downcast_ref::<String>() {
            return s.clone();
        }
        "unknown panic (no readable info; the server stderr still has the panic's file:line)".to_string()
    }
}

impl FileIoServer {
    /// 供 `#[tool_handler(router = ...)]` 使用：派发时套上 panic 兜底层
    fn safe_router(&self) -> PanicSafeRouter<'_> {
        PanicSafeRouter {
            inner: &self.tool_router,
        }
    }
}

#[tool_handler(router = self.safe_router())]
impl ServerHandler for FileIoServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: rmcp::model::ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            server_info: rmcp::model::Implementation::from_build_env(),
            instructions: Some(
                "file-io-mcp file read/write server (directory can be restricted via FILE_IO_ROOT). Safety points the agent MUST follow: \
                 ① Keep the original encoding + BOM + dominant line ending on read/write; encoding distinguishes GBK/UTF-8, and the header hints when uncertain, so specifying encoding explicitly is safest; \
                 ② Overwrite writes are atomic (temp file + rename) and auto-back up before writing, reversible with manage_backups; deletion requires confirm=true; \
                 ③ Always read_text_lines first to get sha256 before editing, and pass expected_sha256 back on write — if someone else changed it you get E_EXTERNAL_CHANGED, re-read then edit, never blindly overwrite; \
                 ④ For multiple changes or when line numbers are unknown use edit_file_sections; regex_replace requires max_matches; when unsure, dry_run=true first to see the diff; \
                 ⑤ On an E_XXX error, fix the input per the message and retry; never ignore errors and force the write. \
                 For full tool selection and the safe-edit loop, see the resource: file-io-mcp://skill/guide (read it via resources/read when needed).".into(),
            ),
        }
    }

    /// Exposes the bundled skill (usage guide) as an MCP resource, so clients auto-discover it via resources/list and
    /// read it via resources/read when needed, without the user manually installing a skill file.
    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        let mut raw = RawResource::new("file-io-mcp://skill/guide", "file-io-mcp usage guide");
        raw.description = Some(
            "Safety usage guide for the file-io-mcp tools: tool selection, the safe-edit loop, required key parameters, and error-code routing.".into(),
        );
        raw.mime_type = Some("text/markdown".into());
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![Resource { raw, annotations: None }],
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        if request.uri == "file-io-mcp://skill/guide" {
            let text = SKILL_DIR
                .get_file("SKILL.md")
                .map(|f| String::from_utf8_lossy(f.contents()).into_owned())
                .unwrap_or_default();
            std::future::ready(Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(text, request.uri)],
            }))
        } else {
            std::future::ready(Err(McpError::invalid_params(
                format!("unknown resource: {}", request.uri),
                None,
            )))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 先装 panic hook：派发处会兜住工具内的 panic，这里负责把它的文本截获下来
    install_panic_hook();

    // 可选的安全沙箱：通过环境变量 FILE_IO_ROOT 限制可访问的根目录。
    // 未设置时不限制路径（向后兼容），但生产环境建议配置以防越权访问。
    let root = match std::env::var("FILE_IO_ROOT") {
        Ok(r) if !r.trim().is_empty() => {
            let p = std::path::PathBuf::from(r.trim());
            let p = if p.is_absolute() {
                p
            } else {
                std::env::current_dir()?.join(p)
            };
            if !p.exists() {
                std::fs::create_dir_all(&p)?;
            }
            let canon = p.canonicalize()?;
            eprintln!("[file-io-mcp] path sandbox enabled, root: {}", canon.display());
            Some(canon)
        }
        _ => {
            eprintln!("[file-io-mcp] warning: FILE_IO_ROOT not set, file access is not path-restricted. For production, configure it to limit the accessible scope.");
            None
        }
    };

    // 命令行参数解析：默认 stdio，--http 启动为 HTTP 模式
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--http") {
        run_http(root).await?;
    } else {
        let service = FileIoServer::new(root).serve(stdio()).await?;
        service.waiting().await?;
    }
    Ok(())
}

/// 启动 Streamable HTTP 模式（单端点 /mcp）
async fn run_http(root: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr: std::net::SocketAddr = args
        .iter()
        .position(|a| a == "--addr" || a == "-a")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| ([0, 0, 0, 0], 3000).into());

    let server_root = root.clone();
    let service: StreamableHttpService<FileIoServer, LocalSessionManager> = StreamableHttpService::new(
        move || {
            Ok(FileIoServer::new(server_root.clone()))
        },
        Default::default(),
        StreamableHttpServerConfig {
            stateful_mode: true,
            sse_keep_alive: Some(std::time::Duration::from_secs(15)),
            ..Default::default()
        },
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("[file-io-mcp] HTTP mode started, listening: http://{}/mcp", addr);
    eprintln!("[file-io-mcp] client connection example: set url = http://{}/mcp in MCP config", addr);
    axum::serve(listener, router).await?;
    Ok(())
}