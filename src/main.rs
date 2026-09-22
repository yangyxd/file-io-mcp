use rmcp::{
    handler::server::wrapper::Parameters,
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_router, tool_handler,
    ErrorData as McpError, ServerHandler, ServiceExt, transport::stdio,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, StreamableHttpServerConfig,
    session::local::LocalSessionManager,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use regex::Regex;
use globset::{Glob, GlobMatcher};
use sha2::{Sha256, Digest};

const MAX_TEXT_READ_SIZE: usize = 10 * 1024 * 1024; // read_text_file 默认最大读取 10MB，超过则在返回头显著标注已截断
const MAX_REGEX_FILE_SIZE: u64 = 64 * 1024 * 1024; // regex_replace 拒绝处理超过 64MB 的文件

/// 文件操作失败后的重试次数（首次执行之外再重试 5 次）
const IO_RETRY_TIMES: usize = 5;
/// 每次重试前的等待时间(毫秒)
const IO_RETRY_DELAY_MS: u64 = 120;

// ==================== 统一错误码 ====================

/// 错误码归类结果：已带码 / 推断出码 / 未识别（由调用方给默认码）
enum ErrorCode {
    AlreadyCoded,
    Known(&'static str),
    Unknown,
}

/// 全部工具的错误都用 `E_XXX 说明` 的形式返回，便于 AI 直接分流处理。
/// 规则按顺序匹配，先命中先用；消息里已显式带 E_ 前缀的不再改写。
/// 第三列表示"参数校验场景也可能命中"——参数校验失败不可能是写入/读取失败，
/// 因此 E_WRITE/E_READ 等运行时码不参与参数类错误的推断。
fn infer_error_code(msg: &str, param_side: bool) -> ErrorCode {
    if msg.starts_with("E_") {
        return ErrorCode::AlreadyCoded;
    }
    #[allow(clippy::type_complexity)]
    const RULES: &[(&[&str], &str, bool)] = &[
        (&["不唯一", "多处匹配", "命中多处"], "E_NOT_UNIQUE", true),
        (&["expected_old", "校验不通过"], "E_GUARD_MISMATCH", true),
        (
            &["编码", "解码", "BOM", "UTF-8", "UTF-16", "U+FFFD"],
            "E_ENCODING",
            true,
        ),
        (&["不存在", "未找到", "无法解析路径"], "E_NOT_FOUND", true),
        (&["匹配数量"], "E_TOO_MANY_MATCHES", true),
        (&["过大", "超出文件大小", "超出允许的根目录"], "E_TOO_LARGE", true),
        (&["权限"], "E_NO_PERMISSION", false),
        (&["HTTP", "请求失败", "响应"], "E_HTTP", false),
        (
            &["读取", "打开文件", "Seek", "元数据", "无法获取文件信息"],
            "E_READ",
            false,
        ),
        (
            &[
                "写入", "追加", "插入", "替换", "复制失败", "移动失败", "创建目录",
                "创建目标目录", "创建父目录", "删除文件失败",
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

/// 参数类错误（默认 E_INVALID_PARAM）——与 McpError::invalid_params 同签名，便于整体替换
fn e_param<M: Into<String>>(message: M, data: Option<serde_json::Value>) -> McpError {
    let msg = message.into();
    let full = match infer_error_code(&msg, true) {
        ErrorCode::AlreadyCoded => msg,
        ErrorCode::Known(code) => format!("{} {}", code, msg),
        ErrorCode::Unknown => format!("E_INVALID_PARAM {}", msg),
    };
    McpError::invalid_params(full, data)
}

/// 运行时错误（默认 E_ERROR）——与 McpError::internal_error 同签名
fn e_internal<M: Into<String>>(message: M, data: Option<serde_json::Value>) -> McpError {
    let msg = message.into();
    let full = match infer_error_code(&msg, false) {
        ErrorCode::AlreadyCoded => msg,
        ErrorCode::Known(code) => format!("{} {}", code, msg),
        ErrorCode::Unknown => format!("E_ERROR {}", msg),
    };
    McpError::internal_error(full, data)
}

// ==================== 文件操作重试 ====================

/// 判断是否属于瞬时性 IO 错误：常见于文件被杀毒软件/索引器/编辑器/备份工具短暂占用，
/// 表现为"没有权限操作文件"(PermissionDenied)，稍等再试通常即可成功。
fn is_retryable_io_error(e: &std::io::Error) -> bool {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::Interrupted => return true,
        _ => {}
    }
    // Windows 下文件被占用时可能只带原始 OS 错误码
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

/// 执行文件操作，遇到瞬时性错误时延时重试：共重试 IO_RETRY_TIMES 次，每次间隔 IO_RETRY_DELAY_MS 毫秒。
/// 非瞬时性错误(如路径不存在、磁盘满等)立即返回，不做无谓等待。
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

// ==================== 参数结构体 ====================

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextFileParams {
    /// 文件路径
    path: String,
    /// 起始字节偏移，默认 0
    offset: Option<u64>,
    /// 读取字节数，默认 10MB 上限（超出会截断并在返回头标注，可配合 offset 分页）
    length: Option<usize>,
    /// 编码，默认自动识别
    encoding: Option<String>,
    /// 每行前显示行号，默认 false
    show_line_numbers: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextLinesParams {
    /// 文件路径
    path: String,
    /// 起始行号(1-based)，默认 1
    start_line: Option<usize>,
    /// 结束行号(1-based，含)，默认到末尾
    end_line: Option<usize>,
    /// 编码，默认自动识别
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteTextFileParams {
    /// 文件路径
    path: String,
    /// 写入内容
    content: String,
    /// 模式：overwrite(默认)/append/insert(需 offset)
    mode: Option<String>,
    /// insert 的插入字节偏移（须落在字符边界）
    offset: Option<u64>,
    /// 编码，默认保持原文件编码（不一致则拒绝）
    encoding: Option<String>,
    /// 期望的旧内容（按 mode 对应：overwrite=全文 / append=末尾 / insert=offset 附近），不符则拒绝并回显实际内容
    expected_old: Option<String>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
    /// true=只返回 diff 预览不写入
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadBinaryFileParams {
    /// 文件路径
    path: String,
    /// 起始字节偏移，默认 0
    offset: Option<u64>,
    /// 读取字节数，默认到末尾
    length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteBinaryFileParams {
    /// 文件路径
    path: String,
    /// 十六进制数据，如 "48656C6C6F"（可带 0x 前缀）
    hex_data: String,
    /// 模式：overwrite(默认)/append/insert/replace
    mode: Option<String>,
    /// insert=插入位置 / replace=替换起始位置（字节）
    offset: Option<u64>,
    /// replace 模式下被替换的字节数
    replace_length: Option<usize>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ManageBackupsParams {
    /// 文件路径
    path: String,
    /// list=列出备份 / undo=回滚最近一次写入或删除 / clean=清理
    action: String,
    /// clean 保留份数，默认 10；0=清空
    keep: Option<usize>,
    /// undo 时文件在备份后又被改过：默认拒绝，true 强制回滚
    force: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileInfoParams {
    /// 文件或目录路径
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RegexReplaceParams {
    /// 文件路径
    path: String,
    /// 正则表达式
    pattern: String,
    /// 替换内容，支持 $1/$2 捕获组
    replacement: String,
    /// 编码，默认自动识别并保持原编码
    encoding: Option<String>,
    /// 全局替换，默认 true；false=只替换首个
    global: Option<bool>,
    /// true=只返回 diff 预览不写入
    dry_run: Option<bool>,
    /// 必填：预期最多替换几处，实际超出即拒绝（防正则过宽误伤）
    max_matches: Option<usize>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TextSearchParams {
    /// 文件或目录（目录则搜索其下文件）
    path: String,
    /// 搜索用正则
    pattern: String,
    /// 区分大小写，默认 true
    case_sensitive: Option<bool>,
    /// 最多返回条数，默认 100
    max_results: Option<usize>,
    /// 后缀过滤，如 "pas"（仅目录模式）
    extension: Option<String>,
    /// 递归子目录，默认 true（仅目录模式）
    recursive: Option<bool>,
    /// 编码，默认 utf-8（多编码文件建议显式指定）
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListFilesParams {
    /// 目录路径
    path: String,
    /// 文件名正则过滤（与 glob_pattern 二选一）
    pattern: Option<String>,
    /// Glob 过滤，如 "*.pas"、"**/*.rs"（与 pattern 二选一）
    glob_pattern: Option<String>,
    /// 递归子目录，默认 false
    recursive: Option<bool>,
    /// 包含目录项，默认 true
    include_dirs: Option<bool>,
    /// 最多返回条数，默认 500
    max_results: Option<usize>,
    /// 显示大小，默认 true
    show_size: Option<bool>,
    /// 显示修改时间，默认 false
    show_modified: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeleteFileParams {
    /// 文件路径
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FetchParams {
    /// 请求 URL
    url: String,
    /// GET(默认)/POST/PUT/DELETE/PATCH/HEAD
    method: Option<String>,
    /// 请求头
    headers: Option<std::collections::HashMap<String, String>>,
    /// 请求体（POST/PUT/PATCH）
    body: Option<String>,
    /// text(默认)/json/binary
    response_type: Option<String>,
    /// 超时(秒)，默认30
    timeout: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileLinesParams {
    /// delete_lines/insert_lines/replace_lines/append_lines
    operation: String,
    /// 文件路径
    path: Option<String>,
    /// 同 path（兼容字段）
    file_path: Option<String>,
    /// 起始行号(1-based)：delete/insert/replace
    start_line: Option<usize>,
    /// 结束行号(1-based，含)：delete/replace；用锚点定位时可省（默认单行）
    end_line: Option<usize>,
    /// insert/replace/append 的内容
    content: Option<String>,
    /// 编码，默认保持原文件编码
    encoding: Option<String>,
    /// delete/replace 必传：目标行的原始内容，用于二次校验防行号算错
    expected_old: Option<String>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
    /// 锚点定位：目标行的完整文本（须全文唯一命中）；与 start_line 二选一
    anchor_text: Option<String>,
    /// 锚点定位：正则匹配目标行（须唯一命中）
    anchor_regex: Option<String>,
    /// 锚点命中多处时选第几处(1-based)，默认要求唯一
    anchor_occurrence: Option<usize>,
    /// true=只返回 diff 预览不写入
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CopyFilesParams {
    /// 源文件路径列表
    sources: Vec<String>,
    /// 目标：目录（多文件）或新文件路径（单文件）
    target: String,
    /// 覆盖已存在的目标，默认 false
    overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MoveFilesParams {
    /// 源文件路径列表
    sources: Vec<String>,
    /// 目标：目录（多文件）或新文件路径（单文件改名）
    target: String,
    /// 覆盖已存在的目标，默认 false
    overwrite: Option<bool>,
}

// ==================== MCP 服务器 ====================

#[derive(Clone)]
struct FileIoServer {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    /// 允许访问的根目录（沙箱）。为 None 时不限制路径。
    root: Option<std::path::PathBuf>,
    /// 同路径串行化锁：保证"读-改-写"对同一文件互斥，多个 AI 并发写同一文件时不互相覆盖。
    /// 用 Arc 包裹，使 Clone 出来的实例共享同一份锁表。
    path_locks: std::sync::Arc<std::sync::Mutex<HashMap<std::path::PathBuf, std::sync::Arc<std::sync::Mutex<()>>>>>,
}

/// 备份相关常量
const BACKUP_DIR_NAME: &str = ".file-io-mcp-backups";
/// 每个文件最多保留的备份份数（超出自动清理最旧的）
const BACKUP_KEEP: usize = 10;
/// 超过该大小的文件不做备份（避免大文件反复占空间）
const BACKUP_MAX_FILE_SIZE: u64 = 20 * 1024 * 1024;

/// 一次写前备份的句柄
struct BackupHandle {
    bak: std::path::PathBuf,
    meta: std::path::PathBuf,
}

/// 是否为本工具内部产生的文件/目录（备份目录 / 原子写入临时文件 / 跨进程锁文件），
/// 列目录与搜索时应跳过，避免污染 AI 的视野
fn is_internal_file(name: &str) -> bool {
    name == BACKUP_DIR_NAME
        || name.ends_with(".file-io-mcp.lock")
        || (name.contains(".file-io-mcp-") && name.ends_with(".tmp"))
}

/// 跨进程锁文件的持有标记：释放(Drop)时删除锁文件
struct FileLockGuard {
    /// 为空表示未取得锁（降级为无锁）
    path: std::path::PathBuf,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// 文件文本：编码 + BOM + 换行风格 + 内容。
/// 保证"读进来是什么样，写回去还是什么样"（BOM 与换行符都不会丢失）。
struct FileText {
    /// 编码规范名，如 "utf-8" / "GBK" / "UTF-16LE"
    encoding: String,
    /// 原文件带有的 BOM 字节；无 BOM 时为空切片
    bom: &'static [u8],
    /// 主换行风格 "\r\n" 或 "\n"，用于新增行
    line_ending: &'static str,
    /// 已剥离 BOM 的正文
    content: String,
    /// 解码时是否出现过无法表示的字节（utf-8 宽松解码），用于提示 AI
    has_invalid: bool,
}

/// 逻辑规范化路径：解析 `.` 和 `..`，并去除 Windows `\\?\` 前缀，
/// 便于做组件级前缀比较（不访问文件系统）。
fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let s = p.to_string_lossy();
    // 去除 Windows 路径前缀 \\?\ 和 \\.\
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

impl FileIoServer {
    fn new(root: Option<std::path::PathBuf>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            root,
            path_locks: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// 取某个路径的串行化锁。同一路径（字符串相同）返回同一把锁。
    fn lock_for(&self, path: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
        let mut map = self
            .path_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.entry(std::path::PathBuf::from(path))
            .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
            .clone()
    }

    /// 在"同路径串行化锁"内执行读-改-写，避免多个 AI 并发写同一文件时互相覆盖。
    /// 两层锁：
    /// 1) 进程内锁（HTTP 模式下多个会话在同一进程内）；
    /// 2) 跨进程锁文件（stdio 模式下每个 AI 是独立进程，进程内锁无效，必须靠锁文件）。
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

    /// 跨进程锁：在目标文件旁创建 `<file>.file-io-mcp.lock`，create_new 成功即获得锁。
    /// 拿不到则等待重试；等待超时或无法创建（只读目录等）时降级为无锁，保证可用性优先。
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
                    // 持有者崩溃残留的锁文件，超期后强行抢占
                    if Self::is_stale_lock(&lock_path, STALE_MS) {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    if waited >= MAX_WAIT_MS {
                        // 让位于可用性：等待过久则不再阻塞（此时仍可依赖 expected_sha256 兜底）
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

    /// 校验并解析路径，确保不超出 root 沙箱（若配置了 root）。
    /// 返回可用于实际文件系统操作的标准化路径字符串。
    fn resolve_path(&self, path: &str) -> Result<String, McpError> {
        let p = std::path::Path::new(path);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| e_internal(format!("无法获取当前目录: {}", e), None))?
                .join(p)
        };

        let root = match &self.root {
            None => return Ok(abs.to_string_lossy().into_owned()),
            Some(r) => r,
        };

        let root_norm = normalize_path(root);
        let abs_norm = normalize_path(&abs);
        if !abs_norm.starts_with(&root_norm) {
            return Err(e_param(
                format!(
                    "路径超出允许的根目录: {} (根目录: {})",
                    path,
                    root.display()
                ),
                None,
            ));
        }

        if abs.exists() {
            let canon = abs.canonicalize().map_err(|e| {
                e_internal(format!("无法解析路径: {}", e), None)
            })?;
            let canon_norm = normalize_path(&canon);
            if !canon_norm.starts_with(&root_norm) {
                return Err(e_param(
                    format!("路径(解析符号链接后)超出允许的根目录: {}", path),
                    None,
                ));
            }
            Ok(canon.to_string_lossy().into_owned())
        } else {
            Ok(abs.to_string_lossy().into_owned())
        }
    }

    /// 确保文件所在目录存在，不存在则自动创建
    fn ensure_parent_dir(path: &str) -> Result<(), String> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.exists() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| format!("创建目录失败 {}: {}", parent.display(), e))?;
            }
        }
        Ok(())
    }

    /// 根据编码名称获取 encoding_rs 的 Encoding 引用
    fn get_encoding(name: &str) -> Result<&'static encoding_rs::Encoding, String> {
        encoding_rs::Encoding::for_label(name.as_bytes())
            .ok_or_else(|| format!("不支持的编码: {}。支持的编码包括: utf-8, gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr, utf-16le, utf-16be, iso-8859-1 等", name))
    }

    /// 将字节按指定编码解码为字符串
    fn decode_bytes(bytes: &[u8], encoding_name: &str) -> Result<String, String> {
        let encoding = Self::get_encoding(encoding_name)?;
        let (cow, _encoding_used, had_errors) = encoding.decode(bytes);
        if had_errors {
            Err(format!("使用 {} 解码失败，数据可能包含无效字节", encoding_name))
        } else {
            Ok(cow.into_owned())
        }
    }

    /// 将字符串按指定编码为字节
    fn encode_string(s: &str, encoding_name: &str) -> Result<Vec<u8>, String> {
        let encoding = Self::get_encoding(encoding_name)?;
        let (cow, _encoding_used, had_errors) = encoding.encode(s);
        if had_errors {
            Err(format!("使用 {} 编码失败，字符串包含该编码无法表示的字符", encoding_name))
        } else {
            Ok(cow.into_owned())
        }
    }

    /// 检测文件头部的 BOM 字节，无 BOM 返回空切片。
    /// 与 detect_encoding 配套使用，写回时原样补回，避免 BOM 丢失导致编码错乱。
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

    /// 自动检测文件编码（只取结果，丢弃置信度）
    fn detect_encoding(bytes: &[u8]) -> &'static str {
        Self::detect_encoding_with_confidence(bytes).0
    }

    /// 自动检测文件编码，并给出置信度。
    /// 核心是可靠区分 GBK 与 UTF-8：不能只看"是否合法 UTF-8"，
    /// 因为部分 GBK 汉字字节序列恰好也是合法 UTF-8（会被解成西里尔/阿拉伯字母而通盘乱码）。
    /// 做法：两种编码都解码一遍，按"像不像中文文本"打分，取分高者；两者接近则标为低置信度。
    fn detect_encoding_with_confidence(bytes: &[u8]) -> (&'static str, bool) {
        // BOM 检测（有 BOM 即确定）
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

        // 无 BOM 的 UTF-16 探测必须先于 UTF-8 判断：
        // UTF-16LE 编码的 ASCII 文本是"ASCII 字节 + 0x00"交替，而 0x00 在 UTF-8 里是合法字符，
        // 若先做 UTF-8 校验会误判成 utf-8，读出满屏 NUL 的"乱码"。
        // 大文件只看头部 64KB（UTF-16 的 NUL 交替特征在开头就非常明显）
        let probe: &[u8] = if bytes.len() > 64 * 1024 {
            &bytes[..64 * 1024]
        } else {
            bytes
        };
        if let Some(enc) = Self::detect_utf16_without_bom(probe) {
            return (enc, true);
        }

        // 纯 ASCII：UTF-8 与 GBK 字节完全一致，判定为 utf-8 无风险
        if bytes.is_empty() || bytes.iter().all(|b| *b < 0x80) {
            return ("utf-8", true);
        }

        // UTF-8 与 GBK 打分对比（非法 UTF-8 记负无穷）。
        // 大文件只取头部样本打分：编码特征在样本上已足够体现，
        // 而全量解码两次 5MB 中文文件要多花几十毫秒
        const SAMPLE_LIMIT: usize = 256 * 1024;
        let sample: &[u8] = if bytes.len() > SAMPLE_LIMIT {
            let raw = &bytes[..SAMPLE_LIMIT];
            // 退到 UTF-8 字符边界：截断处的半截字符会让 UTF-8 解析失败、干扰打分
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
        // 非法字节判定必须全量（防止文件中间的坏字节被漏掉），打分则用样本
        let s_utf8 = match std::str::from_utf8(bytes) {
            Ok(_) => Self::text_likelihood(std::str::from_utf8(sample).unwrap_or("")),
            Err(_) => f64::NEG_INFINITY,
        };
        let s_gbk = Self::text_likelihood(
            &encoding_rs::Encoding::for_label(b"gbk").unwrap().decode(sample).0,
        );

        let (best, best_score) = if s_gbk > s_utf8 {
            ("gbk", s_gbk)
        } else {
            ("utf-8", s_utf8)
        };

        // 两个候选都不像正常文本时，再试其他 CJK 编码，取分最高的一个（置信度标低）
        if !(best_score >= 0.85) {
            let mut alt = (best, best_score);
            for &enc in &["big5", "euc-kr", "shift_jis", "euc-jp"] {
                let s = Self::text_likelihood(
                    &encoding_rs::Encoding::for_label(enc.as_bytes()).unwrap().decode(bytes).0,
                );
                if s > alt.1 {
                    alt = (enc, s);
                }
            }
            return (alt.0, false);
        }

        // 置信度：分数够高，且与另一候选差距明显
        let gap = if s_utf8.is_infinite() || s_gbk.is_infinite() {
            1.0
        } else {
            (s_utf8 - s_gbk).abs()
        };
        (best, best_score >= 0.85 && gap >= 0.1)
    }

    /// 解码后的文本"像不像中文文本"的打分（0.0~1.0）：
    /// 汉字与全角字符加分，替换符/控制字符/无关脚本字符减分。
    /// 用于区分 GBK 与 UTF-8：用错误编码解出来的文本通常满是非预期字符，分数会明显偏低。
    fn text_likelihood(s: &str) -> f64 {
        let mut good = 0.0f64;
        let mut bad = 0.0f64;
        for c in s.chars() {
            match c {
                // CJK 汉字（中文场景的强信号）
                '\u{4E00}'..='\u{9FFF}' => good += 2.0,
                // CJK 标点、全角字符（GBK 文本常见）
                '\u{3000}'..='\u{303F}' | '\u{FF00}'..='\u{FFEF}' => good += 2.0,
                // 空白与 ASCII 可打印字符
                '\t' | '\r' | '\n' | '\u{20}'..='\u{7E}' => good += 1.0,
                // 替换符：说明存在该编码无法表示的字节
                '\u{FFFD}' => bad += 5.0,
                // 其余控制字符
                c if c.is_control() => bad += 5.0,
                // 其他脚本（西里尔、阿拉伯、假名等）与罕见符号：中文文件里不应出现
                _ => bad += 1.0,
            }
        }
        let total = good + bad;
        if total <= 0.0 {
            return 0.0;
        }
        good / total
    }

    /// 判断字节偏移 off 是否落在该编码的字符边界上（用于 insert 类操作，防止把字符劈开）
    fn is_char_boundary(encoding: &str, bytes: &[u8], off: usize) -> bool {
        if off == 0 || off >= bytes.len() {
            return true;
        }
        match encoding.to_ascii_lowercase().as_str() {
            // UTF-8 续字节形如 10xxxxxx
            "utf-8" => (bytes[off] & 0xC0) != 0x80,
            // UTF-16 按 2 字节对齐、UTF-32 按 4 字节对齐（不校验代理项对，够用且不会误拒绝）
            "utf-16le" | "utf-16be" => off % 2 == 0,
            "utf-32le" | "utf-32be" => off % 4 == 0,
            // GBK/Big5 等双字节编码：从最近的 ASCII 字节起逐字符前进，看能否正好停在 off
            _ => {
                let mut start = off;
                while start > 0 && off - start < 8 && bytes[start] >= 0x80 {
                    start -= 1;
                }
                if bytes[start] >= 0x80 {
                    // 起点仍落在多字节字符中间，无法可靠判定 → 放行（宁可不拦也不错拦）
                    return true;
                }
                let mut pos = start;
                while pos < off {
                    pos += if bytes[pos] < 0x80 { 1 } else { 2 };
                }
                pos == off
            }
        }
    }

    /// 新建文件时该编码应自带的 BOM。UTF-16/32 必须带 BOM 才能被再次识别，
    /// 否则会被 detect_encoding 误判成 GBK；UTF-8 等保持不带 BOM（沿用现状）
    fn default_bom_for(encoding: &str) -> &'static [u8] {
        match encoding.to_ascii_lowercase().as_str() {
            "utf-16le" => &[0xFF, 0xFE],
            "utf-16be" => &[0xFE, 0xFF],
            "utf-32le" => &[0xFF, 0xFE, 0x00, 0x00],
            "utf-32be" => &[0x00, 0x00, 0xFE, 0xFF],
            _ => &[],
        }
    }

    /// 探测无 BOM 的 UTF-16：
    /// - LE：偶数位为非零 ASCII、奇数位多为 0x00（如 75 00 6E 00）
    /// - BE：相反（如 00 75 00 6E）
    /// 只有在特征足够强时才判定，避免把含少量 NUL 的二进制/GBK 文件误判成 UTF-16。
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
        // 至少 90% 的码元符合特征，且样本量足够
        let threshold = pairs * 9 / 10;
        if pairs >= 4 && le_hits >= threshold && le_hits > be_hits {
            return Some("utf-16le");
        }
        if pairs >= 4 && be_hits >= threshold && be_hits > le_hits {
            return Some("utf-16be");
        }
        None
    }

    /// 解析 encoding 参数，返回 (编码, 置信度)：
    /// "auto"/未指定时自动检测并给出置信度；显式指定即视为高置信。校验编码有效性。
    /// 低置信度意味着"GBK/UTF-8 难以区分"，读工具应提示 AI 显式指定 encoding
    fn resolve_encoding_with_confidence(
        param: Option<&str>,
        bytes: &[u8],
    ) -> Result<(&'static str, bool), String> {
        match param {
            Some(name) if name.eq_ignore_ascii_case("auto") => {
                Ok(Self::detect_encoding_with_confidence(bytes))
            }
            Some(name) => Ok((Self::get_encoding(name)?.name(), true)),
            None => Ok(Self::detect_encoding_with_confidence(bytes)),
        }
    }

    /// 计算字节的 SHA256 十六进制
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

    /// 版本指纹算法（**唯一口径**，读写与 file_info 全部走这里）：
    /// - ≤1MB：整份内容 sha256
    /// - >1MB：sha256("大小 + 头 64KB + 尾 64KB")，避免为了算 sha 把大文件整个读一遍
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

    /// 版本指纹（内存中已有整份内容时用这个；bytes 必须是文件的完整内容）。
    /// 写入类工具**必须**用它计算返回给 AI 的 sha256，而不是写完后立刻读盘：
    /// Windows 上 rename 替换后立即读取可能仍读到旧缓存页，会返回一个与实际内容不符的指纹，
    /// 导致 AI 拿它当 expected_sha256 时被误判为"文件已被改动"。
    fn fingerprint_short_of_bytes(bytes: &[u8]) -> String {
        let h = Self::fingerprint_of_bytes(bytes);
        h[..16].to_string()
    }

    /// 按路径取版本指纹的完整值；大文件只读头尾各 64KB
    fn file_fingerprint(path: &str, size: u64, bytes: Option<&[u8]>) -> Option<String> {
        const INLINE_MAX: u64 = 1024 * 1024;
        const SAMPLE: usize = 64 * 1024;
        if size <= INLINE_MAX {
            if let Some(b) = bytes {
                if b.len() as u64 == size {
                    return Some(Self::fingerprint_of_bytes(b));
                }
            }
            return fs::read(path).ok().map(|b| Self::fingerprint_of_bytes(&b));
        }
        // 大文件：按 fingerprint_of_bytes 的同构顺序拼 "size + head + tail"
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

    /// 取路径对应的版本指纹（前 16 位，返回给 AI 用），失败返回 "-"
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

    /// 写前版本校验（乐观并发）：expected_sha256 与当前内容不符说明文件已被其他 AI/程序改过，
    /// 直接拒绝本次写入，避免"基于旧内容整文件写回"把别人的修改抹掉。支持前缀匹配。
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
        // 与实际读取工具同一算法（大文件为采样指纹）
        let actual = Self::file_fingerprint(path, current_bytes.len() as u64, Some(current_bytes))
            .unwrap_or_else(|| Self::fingerprint_of_bytes(current_bytes));
        if actual.starts_with(&exp) {
            return Ok(());
        }
        Err(e_param(
            format!(
                "E_EXTERNAL_CHANGED 文件已被修改，拒绝写入！\n文件: {}\n你读取时的 sha256: {}\n当前实际 sha256: {}\n\
                 请重新 read_text_lines/read_text_file 获取最新内容与 sha256 后重试（可只改你那几行，其余保持最新内容）",
                path,
                exp,
                &actual[..16]
            ),
            None,
        ))
    }

    /// 把文件字节解码为 FileText：剥离并记录 BOM、检测主换行风格。
    /// 与 encode_file 严格对称，保证写回后 BOM 不丢（UTF-16 文件不会退化成 GBK 乱码）。
    fn decode_file(bytes: &[u8], encoding_name: &str) -> Result<FileText, String> {
        let bom = Self::detect_bom(bytes);
        let body = &bytes[bom.len()..];
        let lower = encoding_name.to_ascii_lowercase();
        let (content, has_invalid) = if lower == "utf-16le" || lower == "utf-16be" {
            // UTF-16 自行解码，保证与 encode 严格对称
            (Self::decode_utf16(body, lower == "utf-16le")?, false)
        } else if lower == "utf-8" {
            match std::str::from_utf8(body) {
                Ok(s) => (s.to_string(), false),
                Err(_) => (String::from_utf8_lossy(body).into_owned(), true),
            }
        } else {
            let encoding = Self::get_encoding(encoding_name)?;
            let (cow, _used, had_errors) = encoding.decode(body);
            if had_errors {
                return Err(format!("使用 {} 解码失败，数据可能包含无效字节", encoding_name));
            }
            (cow.into_owned(), false)
        };
        let crlf_count = content.matches("\r\n").count();
        let total_lf = content.matches('\n').count();
        let line_ending: &'static str = if crlf_count * 2 > total_lf { "\r\n" } else { "\n" };
        Ok(FileText {
            encoding: encoding_name.to_string(),
            bom,
            line_ending,
            content,
            has_invalid,
        })
    }

    /// UTF-16 解码：按字节序组装 UTF-16 码元后转为字符串
    fn decode_utf16(body: &[u8], little_endian: bool) -> Result<String, String> {
        if body.len() % 2 != 0 {
            return Err("UTF-16 数据字节数为奇数，无法解码（文件可能被截断）".to_string());
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
            .map_err(|_| "UTF-16 解码失败，数据包含无效的代理项对".to_string())
    }

    /// UTF-16 编码：按字节序写出 UTF-16 码元（不含 BOM，BOM 由 encode_file 依原文件补回）
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

    /// 按编码把字符串编码为字节（不含 BOM）
    fn encode_content(encoding: &str, content: &str) -> Result<Vec<u8>, String> {
        let lower = encoding.to_ascii_lowercase();
        if lower == "utf-16le" || lower == "utf-16be" {
            Ok(Self::encode_utf16(content, lower == "utf-16le"))
        } else if lower == "utf-8" {
            Ok(content.as_bytes().to_vec())
        } else {
            Self::encode_string(content, encoding)
        }
    }

    /// 把 FileText 编码回字节：原样补回 BOM
    fn encode_file(ft: &FileText) -> Result<Vec<u8>, String> {
        let mut out: Vec<u8> = ft.bom.to_vec();
        out.extend_from_slice(&Self::encode_content(&ft.encoding, &ft.content)?);
        Ok(out)
    }

    /// 编码的展示名，带 BOM 标记，便于 AI 感知
    fn encoding_label(ft: &FileText) -> String {
        if ft.bom.is_empty() {
            ft.encoding.clone()
        } else {
            format!("{}(BOM)", ft.encoding)
        }
    }

    /// 生成行级 unified diff（公共前后缀裁剪，只输出真正变化的部分）。
    /// 每个方向最多输出 max_lines 行，超出折叠，避免大改动刷屏
    fn unified_diff(old: &str, new: &str, max_lines: usize) -> String {
        if old == new {
            return "  (内容无变化)".to_string();
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
            out.push_str(&format!("  ... 省略 {} 行删除\n", a_mid.len() - max_lines));
        }
        for l in b_mid.iter().take(max_lines) {
            out.push_str(&format!("+ {}\n", l));
        }
        if b_mid.len() > max_lines {
            out.push_str(&format!("  ... 省略 {} 行新增\n", b_mid.len() - max_lines));
        }
        out
    }

    /// 临时文件序号，保证并发写入时临时文件名唯一
    fn tmp_seq() -> u64 {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    // ==================== 备份与回滚 ====================

    /// 备份根目录：默认放在 **MCP 工具自身所在目录** 下的 .file-io-mcp-backups/，
    /// 不污染被编辑的项目目录。可用环境变量 FILE_IO_BACKUP_DIR 覆盖
    /// （exe 目录不可写时也可用它指向可写位置）。
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

    /// 备份 key 归一化：同一文件无论路径来自 canonicalize（Windows 上带 \\?\ 前缀、反斜杠）
    /// 还是普通拼接（正斜杠），都必须得到同一个 key，否则备份会找不回来。
    fn backup_path_key(path: &str) -> String {
        let s = path.replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s
        }
    }

    /// 某文件的备份目录：<备份根>/<文件名>-<绝对路径hash16>/
    /// 文件名 + 路径 hash 组合，既便于人看，又避免同名文件（不同目录）互相覆盖
    fn backup_dir_for(path: &str) -> Option<std::path::PathBuf> {
        let p = std::path::Path::new(path);
        let name = p.file_name()?.to_string_lossy().into_owned();
        // 文件名可能含路径非法字符（极少见），替换掉以免无法建目录
        let safe_name: String = name
            .chars()
            .map(|c| if "\\/:*?\"<>|".contains(c) { '_' } else { c })
            .collect();
        let hash = &Self::sha256_hex(Self::backup_path_key(path).as_bytes())[..16];
        Some(Self::backup_root().join(format!("{}-{}", safe_name, hash)))
    }

    /// 写前备份：优先用硬链接（**工具与被编辑文件同盘时**零拷贝，且后续 rename 替换不会影响它，
    /// 因为原子写是"写临时文件 + rename 替换"，旧内容仍被硬链接引用）；
    /// 工具与被编辑文件不同盘（硬链接跨卷不可用，备份根在工具目录）时自动退化为复制；
    /// 都失败则返回 None（不阻断写入，只是失去回滚能力）。
    /// 目标文件不存在或超过大小上限时不做备份。
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
        // 时间戳 + 序号：保证并发写入时备份名唯一，且字典序即时间序
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
            "restored": false,
        });
        let _ = fs::write(&meta, info.to_string());
        // 备份数量上限：超出即清理最旧的（连同 meta）
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
                // 与读取工具返回的 sha256 同一口径，便于直接比对
                serde_json::Value::String(Self::fingerprint_short_of_bytes(after_bytes)),
            );
        }
        let _ = fs::write(&handle.meta, v.to_string());
    }

    /// 把硬链接备份转成独立副本（就地覆盖写前调用），避免备份内容被一起改写
    fn materialize_hardlink_backup(bak: &std::path::Path) {
        let Ok(data) = fs::read(bak) else {
            return;
        };
        let tmp = bak.with_extension("mat");
        if fs::write(&tmp, &data).is_ok() {
            let _ = fs::rename(&tmp, bak);
        }
    }

    /// 裁剪备份目录：只保留最新的 keep 份（按文件名排序，时间戳在前），多余的连同 meta 删除；
    /// 目录清空后一并删除，避免留一堆空目录
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
        // 目录空了就删掉（含残留的 .mat 临时文件）
        if let Ok(rest) = fs::read_dir(dir) {
            if rest.filter_map(|e| e.ok()).count() == 0 {
                let _ = fs::remove_dir(dir);
            }
        }
    }

    /// 列出某文件的备份（按时间升序）
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
                // 防极端情况下 hash 撞车：meta 记录的原路径必须与本文件一致
                let recorded = v.get("path").and_then(|x| x.as_str())?;
                if !Self::same_path(recorded, path) {
                    return None;
                }
                Some((bak, v))
            })
            .collect()
    }

    /// 路径等价判断（借用备份 key 的归一化规则：分隔符、\\?\ 前缀、Windows 大小写）
    fn same_path(a: &str, b: &str) -> bool {
        Self::backup_path_key(a) == Self::backup_path_key(b)
    }


    /// 原子写入：先写同目录临时文件并落盘，再用 rename 原子替换目标文件。
    /// 好处：任何时刻读到的都是完整的旧文件或完整的新文件，不会读到写了一半的内容。
    /// rename 失败（目标被 IDE/杀软持有句柄等）时回退为就地覆盖写，
    /// 保证"原来能写进去的场景现在依然能写进去"，不会因为原子化反而写不了。
    ///
    /// active_backup：本次写入的备份文件。备份可能是硬链接（与目标共用 inode），
    /// 若走"就地覆盖"回退路径会把备份内容一并污染，因此回退前先把硬链接转成独立副本。
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

        // 1) 写临时文件并强制落盘
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

        // 2) 原子替换
        match retry_io(|| fs::rename(&tmp, p)) {
            Ok(()) => Ok(()),
            Err(_rename_err) => {
                let _ = fs::remove_file(&tmp);
                // 3) 回退：就地覆盖写（非原子，但保证可写性）
                //    就地写会改动 inode 内容，若备份是硬链接会被一起改写，先把它转成独立副本
                if let Some(bak) = active_backup {
                    Self::materialize_hardlink_backup(bak);
                }
                retry_io(|| fs::write(p, bytes))
            }
        }
    }

    /// 写入类操作的写前校验：防止 AI 在未确认当前内容的情况下误写。
    /// expected_old 按 mode 匹配"当前想改范围"的内容：
    /// - overwrite: 整个文件
    /// - append: 文件末尾（追加点）
    /// - insert: 插入点 offset 附近
    /// 不匹配则拒绝写入，并返回该范围的当前内容。
    fn check_write_guard(
        path: &str,
        encoding_name: &str,
        mode: &str,
        offset: Option<u64>,
        expected_old: Option<&str>,
    ) -> Result<(), McpError> {
        let Some(exp) = expected_old else {
            return Ok(());
        };
        if !std::path::Path::new(path).exists() {
            return Err(e_param(
                format!(
                    "文件不存在: {}。已提供 expected_old 说明期望文件存在，请核对路径",
                    path
                ),
                None,
            ));
        }
        let bytes = fs::read(path)
            .map_err(|e| e_internal(format!("读取文件失败: {}", e), None))?;

        // 统一解码入口（剥离 BOM），保证与写入时的内容口径一致
        let actual_content = Self::decode_file(&bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?
            .content;

        // CRLF 归一化：read_text_lines 读取时已去除行尾 \r，比较前统一归一避免误拒
        let norm = |s: &str| s.replace("\r\n", "\n");

        // 按模式确定"当前想改范围"并比对
        let (matched, scope, shown): (bool, String, String) = match mode {
            "append" => {
                // 匹配文件末尾内容（追加点）
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
                (norm(&tail) == norm(exp), "文件末尾(追加点)".to_string(), shown)
            }
            "insert" => {
                // 匹配插入点 offset 附近内容
                let off = offset.unwrap_or(0) as usize;
                let char_off = actual_content.floor_char_boundary(off.min(actual_content.len()));
                let window: String = actual_content[char_off..]
                    .chars()
                    .take(exp.chars().count())
                    .collect();
                let s = actual_content.floor_char_boundary(char_off.saturating_sub(400));
                let shown: String = actual_content[s..].chars().take(800).collect();
                (norm(&window) == norm(exp), format!("插入点 offset={}", off), shown)
            }
            _ => {
                (norm(&actual_content) == norm(exp), "整个文件".to_string(), actual_content.clone())
            }
        };

        if matched {
            return Ok(());
        }
        Err(e_param(
            format!(
                "expected_old 不匹配，拒绝写入！文件可能已被修改或你未完整读取。\n=== 当前想改范围[{}]的实际内容:\n{}",
                scope, shown
            ),
            None,
        ))
    }

    /// 写入类操作的编码决策：
    /// - 文件已存在：检测实际编码；未指定或 auto 时保持原编码写回；
    ///   显式指定编码与实际不一致时直接报错，并返回文件真实编码（防止编码被悄悄改坏）。
    /// - 文件不存在（新建）：按指定编码（默认 utf-8）。
    fn resolve_write_encoding(
        path: &str,
        requested: Option<&str>,
        existing_bytes: Option<&[u8]>,
    ) -> Result<&'static str, McpError> {
        let actual = existing_bytes.map(Self::detect_encoding);
        let req = match requested {
            Some(name) if name.eq_ignore_ascii_case("auto") => None,
            Some(name) => Some(name),
            None => None,
        };
        match (req, actual) {
            (None, Some(act)) => Ok(act),
            (None, None) => Ok("utf-8"),
            (Some(r), None) => {
                let enc = Self::get_encoding(r).map_err(|e| e_param(e, None))?;
                Ok(enc.name())
            }
            (Some(r), Some(act)) => {
                let enc = Self::get_encoding(r).map_err(|e| e_param(e, None))?;
                let rn = enc.name();
                if rn.eq_ignore_ascii_case(act) {
                    return Ok(rn);
                }
                Err(e_param(
                    format!(
                        "编码不一致，拒绝写入！文件 {} 的实际编码是 [{}]，但你指定的编码是 [{}]。直接写入会导致编码混乱。\n\
                         请改用 encoding='{}' 保持原编码后重新调用",
                        path, act, rn, act
                    ),
                    None,
                ))
            }
        }
    }

    /// 递归收集目录下符合后缀过滤的文件路径
    fn collect_files(
        dir: &std::path::Path,
        ext_filter: &Option<String>,
        recursive: bool,
        max_results: usize,
        files: &mut Vec<String>,
    ) -> Result<(), String> {
        let entries = fs::read_dir(dir)
            .map_err(|e| format!("无法读取目录 {}: {}", dir.display(), e))?;

        let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        sorted.sort_by_key(|e| e.file_name());

        for entry in sorted {
            if files.len() >= max_results {
                return Ok(());
            }

            // 跳过本工具自己产生的备份目录 / 临时文件 / 锁文件
            if is_internal_file(&entry.file_name().to_string_lossy()) {
                continue;
            }

            let file_type = entry.file_type().ok();
            let is_dir = file_type.as_ref().map(|ft| ft.is_dir()).unwrap_or(false);
            let is_file = file_type.as_ref().map(|ft| ft.is_file()).unwrap_or(false);

            if is_dir && recursive {
                Self::collect_files(
                    &entry.path(),
                    ext_filter,
                    recursive,
                    max_results,
                    files,
                )?;
                continue;
            }

            if is_file {
                if let Some(ref ext) = ext_filter {
                    let file_ext = entry
                        .path()
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.to_lowercase())
                        .unwrap_or_default();
                    if file_ext != *ext {
                        continue;
                    }
                }
                files.push(entry.path().to_string_lossy().to_string());
            }
        }
        Ok(())
    }
}

#[tool_router]
impl FileIoServer {
    /// 读取文本文件
    #[tool(
        name = "read_text_file",
        description = "按字节读文本片段(offset/length，默认最多 10MB)。返回头: 路径|编码(BOM标注)|大小|sha256|区间；要按行编辑请用 read_text_lines",
        annotations(title = "读取文本文件", read_only_hint = true)
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
            .map_err(|e| e_internal(format!("无法打开文件: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| e_internal(format!("无法获取文件元数据: {}", e), None))?
            .len();

        let start = params.offset.unwrap_or(0);

        // 若需要显示行号且有偏移，需先读取前面的内容数行数
        let prefix_line_count = if show_ln && start > 0 {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;
            let mut prefix_buf = vec![0u8; start as usize];
            file.read_exact(&mut prefix_buf)
                .map_err(|e| e_internal(format!("读取前缀失败: {}", e), None))?;
            // 数前缀中的换行数（即偏移位置处已经过了多少行，行号从1开始，所以行数+1是起始行号）
            prefix_buf.iter().filter(|&&b| b == b'\n').count()
        } else {
            0
        };

        if start >= file_size {
            return Ok(format!("偏移量 {} 超出文件大小 {}", start, file_size));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        let max_len = params.length.unwrap_or(MAX_TEXT_READ_SIZE);
        let read_len = max_len.min(remaining);
        let truncated = read_len < remaining;
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| e_internal(format!("读取失败: {}", e), None))?;

        let (encoding_name, enc_confident) = Self::resolve_encoding_with_confidence(
            params.encoding.as_deref().or(Some("auto")),
            &buffer,
        )
        .map_err(|e| e_param(e, None))?;
        // 从 offset=0 开始读取时，头部可能带 BOM，需剥离并返回给 AI 可见的编码名
        let bom = if start == 0 { Self::detect_bom(&buffer) } else { &[][..] };
        let body = &buffer[bom.len()..];
        let encoding_label = if bom.is_empty() {
            encoding_name.to_string()
        } else {
            format!("{}(BOM)", encoding_name)
        };
        let enc_warn = if enc_confident {
            String::new()
        } else {
            " ⚠️编码识别不确定(GBK/UTF-8 难以区分)，建议显式指定 encoding 后重新读取".to_string()
        };

        let content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8(body.to_vec()).map_err(|_| {
                e_internal(
                    format!("文件不是有效的 UTF-8 编码（可能在偏移量 {} 处包含非法字节），请尝试指定正确的 encoding 参数", start),
                    None,
                )
            })?
        } else {
            Self::decode_bytes(body, encoding_name)
                .map_err(|e| e_internal(e, None))?
        };

        let display_content = if show_ln {
            // 起始行号：前缀的换行数 + 1（1-based）
            let start_line = prefix_line_count + 1;
            let width = (start_line + content.lines().count()).to_string().len().max(3);
            content
                .lines()
                .enumerate()
                .map(|(i, line)| format!("{:>width$}| {}", start_line + i, line, width = width))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            content.clone()
        };

        let trunc_warn = if truncated {
            format!(
                " ⚠️已截断: 文件共 {}B，仅返回 [{},{})。若要完整编辑请改用 read_text_lines，或用 offset 分页读取剩余部分",
                file_size, start, start + read_len as u64
            )
        } else {
            String::new()
        };

        // 版本指纹（供后续写入时作为 expected_sha256 回传，防止并发改动被覆盖）。
        // 大文件用采样指纹，避免"只读一小段却要把整个大文件再读一遍算 sha"
        let sha = Self::path_fingerprint_short(&params.path);

        Ok(format!(
            "{}{}{} | {} | {}B | sha256:{} | [{},{}){}```\n{}\n```",
            params.path,
            trunc_warn,
            enc_warn,
            encoding_label,
            file_size,
            sha,
            start,
            start + read_len as u64,
            if show_ln { " | lines" } else { "" },
            display_content
        ))
    }

    /// 写入文本文件
    #[tool(
        name = "write_text_file",
        description = "整段写文本(自动建目录)。mode=overwrite(默认)/append/insert(需 offset，须落在字符边界)。建议传 expected_old 做写前校验；dry_run=true 只看 diff",
        annotations(title = "写入文本文件", destructive_hint = true)
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

        // 同一文件的读-改-写串行化：多个 AI 并发写同一文件时不会互相覆盖
        self.with_path_lock(&params.path, || {
        // 若文件已存在，读取原字节用于编码检测（写前保持原编码）
        let existing_bytes: Option<Vec<u8>> = if std::path::Path::new(&params.path).exists() {
            Some(fs::read(&params.path).map_err(|e| {
                e_internal(format!("读取原文件失败: {}", e), None)
            })?)
        } else {
            None
        };

        // 写前版本校验：文件已被其他 AI/程序改过则拒绝，避免抹掉别人的修改
        Self::check_expected_sha(
            &params.path,
            existing_bytes.as_deref().unwrap_or(&[]),
            params.expected_sha256.as_deref(),
        )?;

        // 决定写入编码：未指定/auto 时保持原文件编码；指定编码与实际不一致时直接报错返回真实编码
        let encoding_name = Self::resolve_write_encoding(
            &params.path,
            params.encoding.as_deref(),
            existing_bytes.as_deref(),
        )?;

        // 按指定编码将内容转换为字节（不含 BOM；BOM 仅 overwrite 时补在文件头）
        let bytes: Vec<u8> = Self::encode_content(encoding_name, &params.content)
            .map_err(|e| e_internal(e, None))?;

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| e_internal(e, None))?;

        // 写前校验（按 mode 校验"当前想改范围"的内容）：防止未确认当前内容就误写
        Self::check_write_guard(
            &params.path,
            encoding_name,
            mode,
            params.offset,
            params.expected_old.as_deref(),
        )?;

        // BOM 处理：
        // - 文件已存在：原样补回原 BOM，否则编码信息丢失（UTF-16 会退化成 GBK 乱码）
        // - 新建文件：UTF-16/32 必须自带 BOM，否则下次无法被识别，会被误判成 GBK
        let bom: &[u8] = match existing_bytes.as_deref() {
            Some(b) => Self::detect_bom(b),
            None => Self::default_bom_for(encoding_name),
        };
        let encoding_label = if bom.is_empty() {
            encoding_name.to_string()
        } else {
            format!("{}(BOM)", encoding_name)
        };

        // dry-run：只返回 diff 预览，不写文件、不备份
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
                    let mut v = existing_bytes.clone().unwrap_or_default();
                    v.extend_from_slice(&bytes);
                    v
                }
                "insert" => {
                    let original = existing_bytes.clone().ok_or_else(|| {
                        e_param(
                            format!(
                                "insert 模式需要文件已存在，但文件不存在: {}. 请使用 overwrite 模式创建新文件",
                                params.path
                            ),
                            None,
                        )
                    })?;
                    let off = (params.offset.unwrap_or(0) as usize).min(original.len());
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
                "DRY-RUN | {} | {} | mode={} | {}B→{}B | 未写入文件\n{}预计 sha256:{}\n确认无误后去掉 dry_run 重新调用即可写入",
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
                    .map_err(|e| e_internal(format!("E_WRITE 写入失败: {}", e), None))?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &out);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {} | {}B | sha256:{}{}", params.path, encoding_label, out.len(), Self::fingerprint_short_of_bytes(&out), tail))
            }
            "append" => {
                // append 是"就地追加"，硬链接备份会跟着变，因此不做备份（可回滚性由 OCC + 原子写覆盖其他模式）
                let mut full = existing_bytes.clone().unwrap_or_default();
                retry_io(|| {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&params.path)?;
                    file.write_all(&bytes)?;
                    file.flush()?;
                    Ok(())
                })
                .map_err(|e| e_internal(format!("E_WRITE 追加失败: {}", e), None))?;
                full.extend_from_slice(&bytes);
                Ok(format!("OK {} | {} | +{}B append | sha256:{}", params.path, encoding_label, bytes.len(), Self::fingerprint_short_of_bytes(&full)))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                let original = existing_bytes.clone().ok_or_else(|| {
                    e_param(
                        format!("insert 模式需要文件已存在，但文件不存在: {}. 请使用 overwrite 模式创建新文件", params.path),
                        None,
                    )
                })?;
                let off = off.min(original.len());
                // offset 是字节偏移：必须落在字符边界上，否则会把一个多字节字符劈成两半导致乱码
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
                    e_internal(format!("E_WRITE 插入写入失败: {}", e), None)
                })?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {} | +{}B @{} | {}B | sha256:{}{}", params.path, encoding_label, bytes.len(), off, new_data.len(), Self::fingerprint_short_of_bytes(&new_data), tail))
            }
            _ => Ok(format!(
                "不支持的模式: {}，可选: overwrite, append, insert",
                mode
            )),
        }
        })
    }

    /// 按行号读取文本文件（与 edit_file_lines 配合使用，避免行号算错）
    #[tool(
        name = "read_text_lines",
        description = "按行读文本(1-based，带行号)，与 edit_file_lines 配套。返回头含总行数与 sha256；编辑时把 sha256 传给 expected_sha256 可防并发覆盖",
        annotations(title = "按行读取文本", read_only_hint = true)
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
        let bytes = fs::read(&params.path).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    e_internal(format!("文件不存在: {}", params.path), None)
                }
                std::io::ErrorKind::PermissionDenied => {
                    e_internal(format!("没有权限读取文件: {}", params.path), None)
                }
                _ => e_internal(format!("读取文件失败: {}", e), None),
            }
        })?;

        let file_size = bytes.len();
        let (encoding_name, enc_confident) = Self::resolve_encoding_with_confidence(
            params.encoding.as_deref().or(Some("auto")),
            &bytes,
        )
        .map_err(|e| e_param(e, None))?;

        // 统一解码入口：剥离 BOM、记录编码（与 edit_file_lines 完全同一口径）
        let ft = Self::decode_file(&bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?;
        // 行数按与 edit_file_lines 相同的口径统计（split('\n')），但不构造行内容，
        // 避免大文件下为上百万行分配 String；空文件按 0 行处理（否则会被算成"1 个空行"）
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
                format!("行号范围无效: start_line({}) > end_line({})，文件总行数: {}", start, end, total_lines),
                None,
            ));
        }
        if start > total_lines {
            return Err(e_param(
                format!("start_line({}) 超出文件总行数({})", start, total_lines),
                None,
            ));
        }

        // 返回头告警：非法字节、编码识别不确定
        let mut warn = String::new();
        if ft.has_invalid {
            warn.push_str(" ⚠️含非法字节(已按 U+FFFD 替换，写回会永久丢失原字节，建议用二进制工具确认)");
        }
        if !enc_confident {
            warn.push_str(" ⚠️编码识别不确定(GBK/UTF-8 难以区分)，建议显式指定 encoding 后重新读取");
        }

        // 行号显示宽度；只把选中的行格式化成 String（跳过的行零分配）
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
        description = "读二进制 HEX dump(偏移+十六进制+ASCII)，offset/length 截取。返回头含 sha256",
        annotations(title = "读取二进制文件", read_only_hint = true)
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
            .map_err(|e| e_internal(format!("无法打开文件: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| e_internal(format!("无法获取文件元数据: {}", e), None))?
            .len();

        let start = params.offset.unwrap_or(0);
        if start >= file_size {
            return Ok(format!("偏移量 {} 超出文件大小 {}", start, file_size));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        let read_len = params.length.unwrap_or(remaining).min(remaining);
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| e_internal(format!("读取失败: {}", e), None))?;

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
            // 填充对齐
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

        Ok(format!(
            "{} | {}B | sha256:{} | [{},{})```\n{}```",
            params.path,
            file_size,
            Self::path_fingerprint_short(&params.path),
            start,
            start + read_len as u64,
            hex_dump
        ))
    }

    /// 写入十六进制数据到二进制文件
    #[tool(
        name = "write_binary_file",
        description = "按十六进制写二进制。mode=overwrite(默认)/append/insert(offset)/replace(offset+replace_length)",
        annotations(title = "写入二进制文件", destructive_hint = true)
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
        // 兼容处理：去掉 0x 前缀
        let hex_str = params.hex_data.trim();
        let hex_str = if hex_str.starts_with("0x") {
            &hex_str[2..]
        } else {
            hex_str
        };
        // 校验：只允许十六进制字符
        if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let invalid: String = hex_str.chars().filter(|c| !c.is_ascii_hexdigit()).collect();
            return Err(e_param(
                format!("十六进制数据包含非法字符: [{}]。只允许 0-9, A-F, a-f", invalid),
                None,
            ));
        }

        if hex_str.len() % 2 != 0 {
            return Err(e_param(
                "十六进制字符串长度必须为偶数".to_string(),
                None,
            ));
        }

        let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect();
        let bytes = bytes.map_err(|e| {
            e_internal(format!("十六进制解析失败: {}", e), None)
        })?;

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| e_internal(e, None))?;

        // 同一文件的读-改-写串行化 + 写前版本校验
        self.with_path_lock(&params.path, || {
        let current: Vec<u8> = if std::path::Path::new(&params.path).exists() {
            fs::read(&params.path).map_err(|e| {
                e_internal(format!("读取原文件失败: {}", e), None)
            })?
        } else {
            Vec::new()
        };
        Self::check_expected_sha(&params.path, &current, params.expected_sha256.as_deref())?;

        match mode {
            "overwrite" => {
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:overwrite",
                    Some(&current),
                );
                Self::atomic_write_ex(&params.path, &bytes, bak.as_ref().map(|b| b.bak.as_path()))
                    .map_err(|e| e_internal(format!("E_WRITE 写入失败: {}", e), None))?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &bytes);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {}B | sha256:{}{}", params.path, bytes.len(), Self::fingerprint_short_of_bytes(&bytes), tail))
            }
            "append" => {
                let mut full = current.clone();
                retry_io(|| {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&params.path)?;
                    file.write_all(&bytes)?;
                    file.flush()?;
                    Ok(())
                })
                .map_err(|e| e_internal(format!("E_WRITE 追加失败: {}", e), None))?;
                full.extend_from_slice(&bytes);
                Ok(format!("OK {} | +{}B append | sha256:{}", params.path, bytes.len(), Self::fingerprint_short_of_bytes(&full)))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                let original = current;
                let off = off.min(original.len());
                let mut new_data =
                    Vec::with_capacity(original.len() + bytes.len());
                new_data.extend_from_slice(&original[..off]);
                new_data.extend_from_slice(&bytes);
                new_data.extend_from_slice(&original[off..]);
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:insert",
                    Some(&original),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
                    e_internal(format!("E_WRITE 插入写入失败: {}", e), None)
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
                let original = current;

                if off > original.len() {
                    return Ok(format!(
                        "偏移量 {} 超出文件大小 {}",
                        off, original.len()
                    ));
                }

                let end = (off + replace_len).min(original.len());
                let actual_replaced = end - off;

                let mut new_data =
                    Vec::with_capacity(off + bytes.len() + (original.len() - end));
                new_data.extend_from_slice(&original[..off]);
                new_data.extend_from_slice(&bytes);
                new_data.extend_from_slice(&original[end..]);

                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:replace",
                    Some(&original),
                );
                Self::atomic_write_ex(&params.path, &new_data, bak.as_ref().map(|b| b.bak.as_path())).map_err(|e| {
                    e_internal(format!("E_WRITE 替换写入失败: {}", e), None)
                })?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }

                Ok(format!(
                    "OK {} | {}B→{}B @{} | {}B | sha256:{}{}",
                    params.path,
                    actual_replaced,
                    bytes.len(),
                    off,
                    new_data.len(),
                    Self::fingerprint_short_of_bytes(&new_data),
                    tail
                ))
            }
            _ => Ok(format!(
                "不支持的模式: {}，可选: overwrite, append, insert, replace",
                mode
            )),
        }
        })
    }

    /// 搜索文件/目录中的文本内容(正则)
    #[tool(
        name = "text_search",
        description = "在文件/目录中正则搜索，返回 文件:行号:内容(带命中数)。目录默认递归，可 extension 过滤",
        annotations(title = "文本搜索", read_only_hint = true)
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
        let max_results = params.max_results.unwrap_or(100);
        let recursive = params.recursive.unwrap_or(true);
        let encoding_raw = params.encoding.as_deref();
        let encoding_auto = encoding_raw.map_or(false, |e| e.eq_ignore_ascii_case("auto"));

        let pattern_str = if case_sensitive {
            params.pattern.clone()
        } else {
            format!("(?i){}", params.pattern)
        };

        let re = Regex::new(&pattern_str).map_err(|e| {
            e_param(format!("正则表达式错误: {}", e), None)
        })?;

        // 解析后缀过滤（去掉可能的 . 前缀）
        let ext_filter: Option<String> = params.extension.as_ref().map(|e| {
            e.trim_start_matches('.').to_lowercase()
        });

        let path = std::path::Path::new(&params.path);
        let is_dir = path.is_dir();

        // 收集需要搜索的文件列表（使用更大的文件收集上限，避免限制搜索结果）
        let files: Vec<String> = if is_dir {
            let mut files = Vec::new();
            let max_files = max_results * 10; // 收集最多 10 倍于结果数量的文件
            Self::collect_files(path, &ext_filter, recursive, max_files, &mut files)
                .map_err(|e| e_internal(e, None))?;
            files
        } else {
            vec![params.path.clone()]
        };

        let mut results = Vec::new();
        let mut total_matches = 0usize;
        let mut searched_files = 0usize;
        let mut matched_files = 0usize;

        for file_path in &files {
            if results.len() >= max_results {
                break;
            }

            searched_files += 1;
            let mut file_has_match = false;

            if encoding_auto {
                // auto 模式：读取字节 → 检测编码 → 解码 → 搜索
                let bytes = match fs::read(file_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let detected = Self::detect_encoding(&bytes);
                let content = match Self::decode_bytes(&bytes, detected) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for (line_idx, line) in content.lines().enumerate() {
                    if results.len() >= max_results { break; }
                    for mat in re.find_iter(line) {
                        if results.len() >= max_results { break; }
                        total_matches += 1;
                        file_has_match = true;
                        results.push(format!(
                            "  {}:{}:{}  [{}] \"{}\"",
                            file_path,
                            line_idx + 1,
                            mat.start() + 1,
                            mat.as_str(),
                            line.trim()
                        ));
                    }
                }
            } else {
                let encoding_name = encoding_raw.unwrap_or("utf-8");
                let is_utf8 = encoding_name.eq_ignore_ascii_case("utf-8");
                if is_utf8 {
                    // UTF-8 用 BufReader 逐行读取，避免加载整个文件到内存
                    let file = match File::open(file_path) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let reader = BufReader::new(file);
                    for (line_idx, line_result) in reader.lines().enumerate() {
                        if results.len() >= max_results { break; }
                        let line = match line_result {
                            Ok(l) => l,
                            Err(_) => continue,
                        };
                        for mat in re.find_iter(&line) {
                            if results.len() >= max_results { break; }
                            total_matches += 1;
                            file_has_match = true;
                            results.push(format!(
                                "  {}:{}:{}  [{}] \"{}\"",
                                file_path,
                                line_idx + 1,
                                mat.start() + 1,
                                mat.as_str(),
                                line.trim()
                            ));
                        }
                    }
                } else {
                    let bytes = match fs::read(file_path) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let content = match Self::decode_bytes(&bytes, encoding_name) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    for (line_idx, line) in content.lines().enumerate() {
                        if results.len() >= max_results { break; }
                        for mat in re.find_iter(line) {
                            if results.len() >= max_results { break; }
                            total_matches += 1;
                            file_has_match = true;
                            results.push(format!(
                                "  {}:{}:{}  [{}] \"{}\"",
                                file_path,
                                line_idx + 1,
                                mat.start() + 1,
                                mat.as_str(),
                                line.trim()
                            ));
                        }
                    }
                }
            }

            if file_has_match {
                matched_files += 1;
            }
        }

        let truncated = if total_matches > max_results {
            format!("\n... 结果已截断，仅显示前 {} 条（共 {} 个匹配）", max_results, total_matches)
        } else {
            String::new()
        };

        let ext_info = ext_filter.as_ref()
            .map(|e| format!(".{}", e))
            .unwrap_or_default();

        let scope = if is_dir {
            format!("{}", params.path)
        } else {
            format!("{}", params.path)
        };

        Ok(format!(
            "{} | {} | {} | {}/{} files | {} matches{}```\n{}{}```",
            scope,
            params.pattern,
            if case_sensitive { "cs" } else { "ci" },
            matched_files,
            searched_files,
            total_matches,
            if ext_info.is_empty() { String::new() } else { format!(" ext:{} ", ext_info) },
            results.join("\n"),
            truncated
        ))
    }

    /// 正则替换文件文本
    #[tool(
        name = "regex_replace",
        description = "正则替换(支持 $1/$2 捕获组)。max_matches 必填=预期最多替换几处，实际超出即拒绝(防正则过宽误伤)；global 默认 true；dry_run=true 只看 diff",
        annotations(title = "正则替换", destructive_hint = true)
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
            .map_err(|e| e_internal(format!("无法获取文件信息: {}", e), None))?
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
            e_internal(format!("读取文件失败: {}", e), None)
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

        let re = Regex::new(&params.pattern).map_err(|e| {
            e_param(format!("正则表达式错误: {}", e), None)
        })?;

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
            re.replace_all(&content, params.replacement.as_str()).into_owned()
        } else {
            re.replacen(&content, 1, params.replacement.as_str()).into_owned()
        };

        // dry-run：只预览不写入
        if params.dry_run.unwrap_or(false) {
            let mut preview = String::new();
            for (i, mat) in re.find_iter(&content).take(20).enumerate() {
                let replaced = re
                    .captures_at(&content, mat.start())
                    .map(|caps| {
                        let mut out = String::new();
                        caps.expand(params.replacement.as_str(), &mut out);
                        out
                    })
                    .unwrap_or_else(|| params.replacement.clone());
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
            e_internal(format!("E_WRITE 写入文件失败: {}", e), None)
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
        description = "列目录/按文件名搜索(glob_pattern 或 pattern 正则，二选一)，可 recursive、include_dirs、show_size/show_modified",
        annotations(title = "列出目录", read_only_hint = true)
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
        let max_results = params.max_results.unwrap_or(500);
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
        ) -> Result<(), String> {
            *scanned_dirs += 1;
            let entries_dir = fs::read_dir(dir_path)
                .map_err(|e| format!("无法读取目录 {}: {}", dir_path.display(), e))?;
            let mut sorted: Vec<_> = entries_dir.filter_map(|e| e.ok()).collect();
            sorted.sort_by_key(|e| e.file_name());
            for entry in sorted {
                if entries.len() >= max_results { return Ok(()); }
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
                        scanned_dirs, total_size,
                    )?;
                    if entries.len() >= max_results { return Ok(()); }
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
        )
        .map_err(|e| e_internal(e, None))?;

        let truncated = if entries.len() >= max_results {
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
        description = "文件/目录元信息：路径|类型|大小|mtime(秒)|sha256。sha256 与读工具同源，可直接当 expected_sha256 用",
        annotations(title = "获取文件信息", read_only_hint = true)
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
            e_internal(format!("无法获取文件信息: {}", e), None)
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

        Ok(format!(
            "{} | {} | {}B | {} | sha256:{}",
            params.path, file_type, metadata.len(), modified_str, hash
        ))
    }

    /// 删除文件(需用户确认)
    #[tool(
        name = "delete_file",
        description = "删除单个文件(不可删目录)。删除前自动备份，可用 manage_backups undo 恢复",
        annotations(title = "删除文件", destructive_hint = true)
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

        // 与该文件的写操作互斥，避免"边写边删"
        let lock = self.lock_for(&params.path);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());

        if !path.exists() {
            return Ok(format!("文件不存在: {}", params.path));
        }

        if !path.is_file() {
            return Ok(format!("路径不是普通文件，无法删除: {}", params.path));
        }

        let size = fs::metadata(path)
            .map_err(|e| e_internal(format!("E_NOT_FOUND 无法获取文件信息: {}", e), None))?
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
        description = "备份管理(备份存于工具自身目录，不污染项目；每文件最多留 10 份，超出自动清理)。list=列出 / undo=回滚最近一次写入或删除(文件之后又被改动时默认拒绝，force=true 强制) / clean=清理",
        annotations(title = "备份管理", destructive_hint = true)
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

        // 与该文件的写操作互斥
        let lock = self.lock_for(&params.path);
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());

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

    /// 发送HTTP请求
    #[tool(
        name = "fetch",
        description = "HTTP 请求(GET/POST/PUT/DELETE/PATCH/HEAD)。文本响应超 100KB 会截断并标注总大小",
        annotations(title = "HTTP 请求", open_world_hint = true)
    )]
    async fn fetch(
        &self,
        Parameters(params): Parameters<FetchParams>,
    ) -> Result<String, McpError> {
        let method = params.method.as_deref().unwrap_or("GET").to_uppercase();
        let timeout_secs = params.timeout.unwrap_or(30);
        let response_type = params.response_type.as_deref().unwrap_or("text");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| e_internal(format!("创建 HTTP 客户端失败: {}", e), None))?;

        let mut request = match method.as_str() {
            "GET" => client.get(&params.url),
            "POST" => client.post(&params.url),
            "PUT" => client.put(&params.url),
            "DELETE" => client.delete(&params.url),
            "PATCH" => client.patch(&params.url),
            "HEAD" => client.head(&params.url),
            _ => {
                return Ok(format!(
                    "不支持的 HTTP 方法: {}，可选: GET, POST, PUT, DELETE, PATCH, HEAD",
                    method
                ));
            }
        };

        if let Some(ref headers) = params.headers {
            for (key, value) in headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        if let Some(ref body) = params.body {
            request = request.body(body.clone());
        }

        let response = request
            .send()
            .await
            .map_err(|e| e_internal(format!("请求失败: {}", e), None))?;

        let status = response.status().as_u16();
        let status_text = response.status().canonical_reason().unwrap_or("Unknown");

        let mut resp_headers = Vec::new();
        for (key, value) in response.headers().iter() {
            if let Ok(v) = value.to_str() {
                resp_headers.push(format!("{}: {}", key, v));
            }
        }
        let status_line = format!("{} {}", status, status_text);
        let headers_block = if resp_headers.is_empty() {
            "\n".to_string()
        } else {
            format!("\n{}\n---\n", resp_headers.join("\n"))
        };

        match response_type {
            "json" => {
                let body = response.text().await.map_err(|e| {
                    e_internal(format!("读取响应失败: {}", e), None)
                })?;
                let formatted = serde_json::from_str::<serde_json::Value>(&body)
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or(body.clone()))
                    .unwrap_or(body);

                Ok(format!(
                    "{}{}```\n{}\n```",
                    status_line, headers_block, formatted
                ))
            }
            "binary" => {
                let bytes = response.bytes().await.map_err(|e| {
                    e_internal(format!("读取响应失败: {}", e), None)
                })?;
                let hex_preview: String = bytes
                    .iter()
                    .take(256)
                    .map(|b| format!("{:02X} ", b))
                    .collect();
                let truncated = if bytes.len() > 256 {
                    format!("\n... {}B total", bytes.len())
                } else {
                    String::new()
                };

                Ok(format!(
                    "{}{}```\n{}{}```",
                    status_line, headers_block, hex_preview, truncated
                ))
            }
            _ => {
                // text
                let body = response.text().await.map_err(|e| {
                    e_internal(format!("读取响应失败: {}", e), None)
                })?;

                let preview = if body.len() > 100_000 {
                    // 按字符边界截断：第 10 万字节可能落在多字节字符中间，直接切片会 panic
                    let cut = body.floor_char_boundary(100_000);
                    format!("{}\n... {}B total", &body[..cut], body.len())
                } else {
                    body
                };

                Ok(format!(
                    "{}{}```\n{}\n```",
                    status_line, headers_block, preview
                ))
            }
        }
    }

    /// 复制文件
    #[tool(
        name = "copy_files",
        description = "复制文件(自动建目录)：多文件时 target 视为目录，单文件可指定新路径/文件名；已存在默认跳过，overwrite=true 覆盖",
        annotations(title = "复制文件", destructive_hint = true)
    )]
    fn copy_files(
        &self,
        Parameters(params): Parameters<CopyFilesParams>,
    ) -> Result<String, McpError> {
        let overwrite = params.overwrite.unwrap_or(false);
        let target = self.resolve_path(&params.target)?;
        let target_path = std::path::Path::new(&target);
        let target_is_dir = target_path.is_dir() || !target_path.exists();

        // 解析所有源文件路径
        let sources: Vec<String> = params.sources.iter()
            .map(|s| self.resolve_path(s))
            .collect::<Result<Vec<_>, _>>()?;

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
                continue;
            }

            let size = fs::metadata(src)
                .map_err(|e| e_internal(format!("无法读取源文件信息: {}", e), None))?
                .len();

            // 与目标文件的其他写操作互斥
            let lock = self.lock_for(&dest.to_string_lossy());
            let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            retry_io(|| fs::copy(src, &dest))
                .map_err(|e| e_internal(format!("复制失败 {} -> {}: {}", src, dest.display(), e), None))?;

            copied += size;
            results.push(format!("OK {} -> {} | {}B", src, dest.display(), size));
        }

        Ok(format!(
            "{} | {} files | {}B copied\n{}",
            if target_is_dir { target.to_string() } else { target_path.to_string_lossy().to_string() },
            results.len(),
            copied,
            results.join("\n"),
        ))
    }

    /// 移动/重命名文件
    #[tool(
        name = "move_files",
        description = "移动/重命名文件(自动建目录)：多文件时 target 视为目录，单文件可指定新路径/文件名；已存在默认跳过，overwrite=true 覆盖",
        annotations(title = "移动文件", destructive_hint = true)
    )]
    fn move_files(
        &self,
        Parameters(params): Parameters<MoveFilesParams>,
    ) -> Result<String, McpError> {
        let overwrite = params.overwrite.unwrap_or(false);
        let target = self.resolve_path(&params.target)?;
        let target_path = std::path::Path::new(&target);
        let target_is_dir = target_path.is_dir() || !target_path.exists();

        // 解析所有源文件路径
        let sources: Vec<String> = params.sources.iter()
            .map(|s| self.resolve_path(s))
            .collect::<Result<Vec<_>, _>>()?;

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
                continue;
            }

            let size = fs::metadata(src)
                .map_err(|e| e_internal(format!("无法读取源文件信息: {}", e), None))?
                .len();

            // 与源/目标文件的其他写操作互斥
            let lock = self.lock_for(&dest.to_string_lossy());
            let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let lock_src = self.lock_for(src);
            let _guard_src = lock_src.lock().unwrap_or_else(|e| e.into_inner());
            retry_io(|| fs::rename(src, &dest))
                .map_err(|e| e_internal(format!("移动失败 {} -> {}: {}", src, dest.display(), e), None))?;

            moved += size;
            results.push(format!("OK {} -> {} | {}B", src, dest.display(), size));
        }

        Ok(format!(
            "{} | {} files | {}B moved\n{}",
            if target_is_dir { target.to_string() } else { target_path.to_string_lossy().to_string() },
            results.len(),
            moved,
            results.join("\n"),
        ))
    }

    /// 按行编辑文件：删除/插入/替换/追加行
    #[tool(
        name = "edit_file_lines",
        description = "按行编辑(1-based)：delete_lines/insert_lines/replace_lines/append_lines。定位用 anchor_text(整行文本，须全文唯一)或 anchor_regex，也可直接给 start_line/end_line；delete/replace 必传 expected_old 二次校验；dry_run=true 只看 diff",
        annotations(title = "按行编辑文件", destructive_hint = true)
    )]
    fn edit_file_lines(
        &self,
        Parameters(params): Parameters<EditFileLinesParams>,
    ) -> Result<String, McpError> {
        let target = params.path.or(params.file_path).ok_or_else(|| {
            e_param("缺少 path 或 file_path 参数", None)
        })?;
        let target = self.resolve_path(&target)?;

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
                _ => e_internal(format!("读取文件失败: {}", e), None),
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

        // 辅助：对期望旧内容进行比对（用于防止行号算错）
        let check_expected_old = |range: std::ops::Range<usize>, expected: &str| -> Result<(), McpError> {
            let actual_lines: Vec<String> = lines[range.clone()]
                .iter()
                .map(|s| s.trim_end_matches('\r').to_string())
                .collect();
            // 逐行比较，兼容 \r\n
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
                return Err(e_param(
                    format!(
                        "expected_old 不匹配！行号可能算错了。期望 {}~{} 行的实际内容与提供的 expected_old 不一致。\n\
                         文件总行数: {}\n\
                         === 期望内容({}行):\n{}\n\
                         === 实际内容(上下文 >>> 标记目标行):\n{}",
                        range.start + 1,
                        range.end,
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
        let mut start_line = params.start_line;
        let mut end_line = params.end_line;
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

        let result = match params.operation.as_str() {
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
                        format!("行号范围无效: {}-{}，文件总行数: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = params.expected_old.as_deref().ok_or_else(|| {
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
                    e_param("插入行操作需要指定 content", None)
                })?;
                if start < 1 || start > total_lines + 1 {
                    return Err(e_param(
                        format!("插入位置无效: {}，文件总行数: {}", start, total_lines),
                        None,
                    ));
                }
                // 拆分插入内容，兼容 \r\n
                let insert_lines: Vec<String> = insert_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                let idx = start - 1;
                let mut new = Vec::with_capacity(total_lines + insert_lines.len());
                new.extend(modified.drain(..idx));
                new.extend(insert_lines);
                new.extend(modified);
                modified = new;
                format!("ins @{}", start)
            }

            "replace_lines" => {
                let start = start_line.ok_or_else(|| {
                    e_param("替换行操作需要指定 start_line 或 anchor_text/anchor_regex", None)
                })?;
                let end = end_line.unwrap_or(start);
                if end < start {
                    return Err(e_param(
                        format!("行号范围无效: {}-{}", start, end),
                        None,
                    ));
                }
                let replace_content = params.content.as_ref().ok_or_else(|| {
                    e_param("替换行操作需要指定 content", None)
                })?;
                if start < 1 || end > total_lines || start > end {
                    return Err(e_param(
                        format!("行号范围无效: {}-{}，文件总行数: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = params.expected_old.as_deref().ok_or_else(|| {
                    e_param(
                        "replace_lines 必须提供 expected_old（将 read_text_lines 读到的目标行原样传入），用于防止行号算错",
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
                    e_param("追加行操作需要指定 content", None)
                })?;
                let append_lines: Vec<String> = append_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                modified.extend(append_lines);
                format!("append")
            }

            _ => {
                return Err(e_param(
                    format!(
                        "不支持的操作类型: {}，可选: delete_lines, insert_lines, replace_lines, append_lines",
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
                "DRY-RUN | {} | {} | {} | {}→{} lines | {}B→{}B | 未写入文件\n{}预计 sha256:{}\n确认无误后去掉 dry_run 重新调用即可写入",
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
                e_internal(format!("E_NO_PERMISSION 没有权限操作文件: {}", target), None)
            } else {
                e_internal(format!("E_WRITE 写入文件失败: {}", e), None)
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
}

#[tool_handler]
impl ServerHandler for FileIoServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: rmcp::model::ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: rmcp::model::Implementation::from_build_env(),
            instructions: Some(
                "文件读写服务器（可用 FILE_IO_ROOT 限制可访问目录）。通用约定：\
                 ① 读写保持原编码+BOM+主换行风格；编码自动识别（可区分 GBK/UTF-8），识别不确定时返回头会提示；\
                 ② 覆盖类写入是原子的（临时文件+rename），写前自动备份到工具自身目录，可用 manage_backups 回滚；\
                 ③ 读工具返回头带 sha256（文件指纹）；写入时把上次读到的值传给 expected_sha256，\
                    若文件已被他人改动会返回 E_EXTERNAL_CHANGED，此时请重新读取后再改，不要盲目覆盖；\
                 ④ 改文件前先 read_text_lines 取内容与 sha256；不确定改法时先传 dry_run=true 看 diff 再实写。\
                 错误码：E_NOT_FOUND/E_NOT_UNIQUE/E_GUARD_MISMATCH/E_EXTERNAL_CHANGED/E_ENCODING/\
                 E_NO_PERMISSION/E_READ/E_WRITE/E_TOO_LARGE/E_TOO_MANY_MATCHES/E_INVALID_PARAM。\
                 fetch 会访问外部网络。".into(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            eprintln!("[file-io-mcp] 已启用路径沙箱，根目录: {}", canon.display());
            Some(canon)
        }
        _ => {
            eprintln!("[file-io-mcp] 警告: 未设置 FILE_IO_ROOT，文件访问不限制路径。生产环境建议配置以限制可访问范围。");
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
    eprintln!("[file-io-mcp] HTTP 模式已启动，监听: http://{}/mcp", addr);
    eprintln!("[file-io-mcp] 客户端连接示例: MCP 配置中设置 url = http://{}/mcp", addr);
    axum::serve(listener, router).await?;
    Ok(())
}