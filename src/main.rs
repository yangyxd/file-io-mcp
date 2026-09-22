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
use std::io::{Read, Seek, SeekFrom, Write};
use regex::Regex;
use globset::{Glob, GlobMatcher};
use sha2::{Sha256, Digest};

const MAX_TEXT_READ_SIZE: usize = 10 * 1024 * 1024; // read_text_file 默认最大读取 10MB，超过则在返回头显著标注已截断
/// read_text_file / read_binary_file 单次读取的硬上限（length 传超大也不越过，防内存/响应失控）
const MAX_READ_HARD_LIMIT: usize = 64 * 1024 * 1024;
/// read_binary_file 单次最多 dump 的字节数（HEX dump 体积约为原字节的 4~5 倍）
const MAX_BINARY_DUMP_LIMIT: usize = 4 * 1024 * 1024;
/// read_text_lines 允许整份读入内存的文件大小上限（该工具按行工作，无法分页）
const MAX_TEXT_LINES_FILE_SIZE: u64 = 64 * 1024 * 1024;

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
        // 沙箱越界属于权限问题，单独归类（不要混进 E_TOO_LARGE）
        (&["超出允许的根目录"], "E_NO_PERMISSION", true),
        (&["过大", "超出文件大小"], "E_TOO_LARGE", true),
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
    /// 读取字节数，默认 10MB 上限（超出会截断并在返回头标注，可配合 offset 分页）；必须 ≥1。
    /// 注意：非 strict 时它只是“提示值”——为覆盖完整多字节字符可能多读几字节、offset 可能下取整
    length: Option<usize>,
    /// true=按字节精确读取：不做“至少读 4 字节”、不对 offset 下取整；
    /// 边缘切在字符中间时丢弃不完整字节，并在返回头标注
    strict: Option<bool>,
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
    /// 读取字节数，默认到末尾；单次最多 dump 4MB（超出会截断并在返回头标注 ⚠️已截断）
    length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteBinaryFileParams {
    /// 文件路径
    path: String,
    /// 十六进制数据，如 "48656C6C6F"（可带 0x 前缀与空格/冒号等分隔符）；
    /// 空串 = 0 字节：仅 replace 可用于删除字节，overwrite 需配 confirm=true
    hex_data: String,
    /// 模式：overwrite(默认)/append/insert/replace
    mode: Option<String>,
    /// insert=插入位置 / replace=替换起始位置（字节）
    offset: Option<u64>,
    /// replace 模式下被替换的字节数
    replace_length: Option<usize>,
    /// 期望的旧字节(HEX，可带 0x 前缀与空格/冒号分隔)。按 mode 校验"待改范围"：
    /// overwrite=全文 / append=文件末尾 / insert=offset 起 / replace=[offset, offset+replace_length)；
    /// 不符则拒绝写入并回显该位置的实际字节（防 offset 算错）
    expected_hex: Option<String>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
    /// true=只返回 HEX diff 预览与预计指纹，不写文件
    dry_run: Option<bool>,
    /// 显式确认：hex_data 为空时 overwrite 会把文件清空为 0 字节，必须传 true 才执行
    confirm: Option<bool>,
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
    /// 匹配模式；默认按正则解析，literal=true 时按纯文本解析
    pattern: String,
    /// true=pattern 按纯文本处理（自动转义，元字符不再生效），replacement 里的 $ 也按字面量填入
    literal: Option<bool>,
    /// 替换内容，支持 $1/$2 捕获组（literal=true 时按字面量填入）
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
    /// 搜索内容：mode=literal 时按普通文本；mode=regex 时按正则
    pattern: String,
    /// 匹配模式：regex(默认，正则) / literal(普通文本，pattern 里的 . * [ 等一律当字面量，不用转义)
    mode: Option<String>,
    /// 区分大小写，默认 true
    case_sensitive: Option<bool>,
    /// 最多返回条数，默认 100
    max_results: Option<usize>,
    /// 后缀过滤(单个)，如 "pas"；等价于 extensions 只写一项（仅目录模式）
    extension: Option<String>,
    /// 后缀过滤(多个)，如 ["pas","pp"]，命中任一即可（仅目录模式）
    extensions: Option<Vec<String>>,
    /// 递归子目录，默认 true（仅目录模式）
    recursive: Option<bool>,
    /// 编码，默认 auto（逐文件自动识别，可区分 GBK/UTF-8）；显式指定则只按该编码解码
    encoding: Option<String>,
    /// 跳过隐藏文件与隐藏目录（以 . 开头，如 .git/.env），默认 true；false=全都搜（仅目录模式）
    skip_hidden: Option<bool>,
    /// 仅搜索匹配这些 glob 的文件，如 ["*.rs","src/**/*.ts"]；任一命中即可（仅目录模式）
    include: Option<Vec<String>>,
    /// 跳过匹配这些 glob 的文件/目录，如 ["*.min.js","node_modules/**"]；目录命中即整棵剪枝（仅目录模式）
    exclude: Option<Vec<String>>,
    /// 目录模式下最多收集多少个文件，默认 max_results*10；达到上限会在结果中告警
    max_files: Option<usize>,
    /// 命中行前后各显示多少行上下文，默认 0（>0 时同一文件的相邻命中会合并显示）
    context_lines: Option<usize>,
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
    /// 删前确认：必须显式传 true 才会真正删除；未传(false)时返回提示不删，防止误删
    confirm: Option<bool>,
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
    /// 【已废弃，仅为兼容旧调用保留】同 path，请改用 path
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

/// 批量片段编辑中的单条编辑：在原文中精确找到 expected_old，替换为 content
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SectionEdit {
    /// 待替换的原始片段（须与文件内容逐字符一致，可含多行；读到的换行是 \r\n 也可写成 \n）
    expected_old: String,
    /// 替换成的新内容；空串 = 删除该片段
    content: String,
    /// 当 expected_old 命中多处时选第几处(1-based)，默认要求全文唯一
    occurrence: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileSectionsParams {
    /// 文件路径
    path: String,
    /// 待替换片段列表（各自基于**同一次快照**定位，允许一次改多处）
    edits: Vec<SectionEdit>,
    /// 编码，默认保持原文件编码（不一致则拒绝）
    encoding: Option<String>,
    /// 读到的 sha256；文件已被改动则拒绝写入
    expected_sha256: Option<String>,
    /// true(默认)=任一片段未命中/不唯一就整体不写；false=只写命中的那些，并在结果里列出被跳过的
    all_or_nothing: Option<bool>,
    /// true=只返回 diff 预览不写入
    dry_run: Option<bool>,
}


// ==================== MCP 服务器 ====================

#[derive(Clone)]
struct FileIoServer {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    /// 允许访问的根目录（沙箱）。为 None 时不限制路径。
    root: Option<std::path::PathBuf>,
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

/// 目录扫描统计：用于向调用方解释"搜到了什么、为什么可能没搜全"
#[derive(Default)]
struct SearchScanStat {
    /// 被 include/exclude/extension 过滤掉的文件数
    filtered: usize,
    /// 因 exclude 被整棵剪枝的目录数
    pruned_dirs: usize,
    /// 是否因达到 max_files 上限而提前停止（目录可能未完全覆盖）
    capped: bool,
}

impl FileIoServer {
    fn new(root: Option<std::path::PathBuf>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            root,
        }
    }

    /// 取某个路径的串行化锁。同一路径（字符串相同）返回同一把锁。
    /// 用**进程级**全局锁表：HTTP 模式下每个会话是独立的 FileIoServer 实例，
    /// 只有全局表才能让不同会话共享同一把锁（否则“同进程多会话互斥”的承诺并不成立）。
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
        // 长跑的 HTTP 服务里路径会越积越多：表过大时清理掉“没人持有”的锁
        // （Arc 强引用计数为 1 说明只有本表在引用它，此时可安全移除）
        if map.len() > 4096 {
            map.retain(|_, v| std::sync::Arc::strong_count(v) > 1);
        }
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
    /// 返回值同时用于**文件系统操作**与**回显**，因此要求：
    /// 1) 稳定：同一文件的各种写法（相对/绝对/含 `..`/大小写不同）映射到同一字符串，
    ///    否则锁键与备份分区会分裂（备份 key 另见 `backup_path_key`，它按绝对形式再归一一次）；
    /// 2) 可读：在**当前目录之下**的文件回显相对路径（如 `src\main.rs`），
    ///    其余回显去掉 `\\?\` 的绝对路径（`\\?\F:\a` → `F:\a`）。
    /// 相对写法必须以当前目录为基准——文件系统层就是这样解析相对路径的；
    /// 若改用别的基准（如沙箱 root）回显，回显出的相对路径会被写到别处。
    fn resolve_path(&self, path: &str) -> Result<String, McpError> {
        let cwd = std::env::current_dir()
            .map_err(|e| e_internal(format!("无法获取当前目录: {}", e), None))?;

        let p = std::path::Path::new(path);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };

        // 先解析为"尽量真实"的路径：最长存在前缀由 OS canonicalize（统一大小写、展开 8.3 短名、
        // 解析符号链接/junction），不存在的尾部按普通段原样拼接；无法安全解析时退回文本规范化。
        // 这样"根目录内但写法不同"的路径不会被子串比较误拒，而越界/链接逃逸仍会被拦下。
        let resolved = Self::resolve_existing_prefix(&abs);

        if let Some(r) = &self.root {
            if !Self::sandbox_within(&resolved, r) {
                return Err(e_param(
                    format!(
                        "路径超出允许的根目录: {} (根目录: {})",
                        path,
                        r.display()
                    ),
                    None,
                ));
            }
        }

        Ok(Self::display_path(&resolved, &cwd))
    }

    /// 去掉 Windows 扩展长度前缀：`\\?\F:\a` → `F:\a`、`\\?\UNC\srv\share\a` → `\\srv\share\a`。
    /// `\\?\` 形式可读性差，会禁用后续路径规范化，不适合回显给调用方。
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

    /// 生成回显路径：位于 base（当前目录）之下时返回相对写法，否则返回去掉 `\\?\` 的绝对路径。
    /// base 必须是当前目录，这样调用方把回显的相对路径再传回来时能被正确解析。
    /// 入参须是已规范化的绝对路径（不含 `.`/`..`）。
    fn display_path(resolved: &std::path::Path, base: &std::path::Path) -> String {
        let plain = Self::strip_verbatim_prefix(resolved);
        let base_plain = Self::strip_verbatim_prefix(base);
        match plain.strip_prefix(&base_plain) {
            // 就是基准目录本身
            Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
            Ok(rel) => rel.to_string_lossy().into_owned(),
            Err(_) => plain.to_string_lossy().into_owned(),
        }
    }

    /// 判断 IO 错误是否为“跨设备/跨卷”（Windows ERROR_NOT_SAME_DEVICE=17，Unix EXDEV=18），
    /// 用于把 move 回退成“复制 + 删除”。
    fn is_cross_device_error(e: &std::io::Error) -> bool {
        // 17/18 是两个平台各自的“跨设备”错误码，含义并不互通：
        // Windows ERROR_NOT_SAME_DEVICE=17；Unix EXDEV=18。
        // 若在 Windows 上认 18，会把 ERROR_NO_MORE_FILES(18) 误判成跨卷。
        #[cfg(windows)]
        {
            matches!(e.raw_os_error(), Some(17))
        }
        #[cfg(not(windows))]
        {
            matches!(e.raw_os_error(), Some(18))
        }
    }

    /// 路径是否位于沙箱根目录之下（含根目录自身）。按**路径组件**比较，
    /// 避免 "C:\data" 误把同前缀的 "C:\data-evil" 当作根内路径放行。
    fn sandbox_within(path: &std::path::Path, root: &std::path::Path) -> bool {
        let p = std::path::PathBuf::from(Self::sandbox_cmp_key(path));
        let r = std::path::PathBuf::from(Self::sandbox_cmp_key(root));
        p.starts_with(&r)
    }

    /// 判定 target 应视为目录还是文件路径（resolved 为已解析绝对路径，raw 为调用方原始入参）：
    /// - target 已存在：以文件系统实际类型为准
    /// - target 不存在：多文件时为目录；单文件时为新文件路径（可改名），
    ///   除非原始入参以 `/` 或 `\` 结尾（显式表明要放进目录）
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

    /// 编码识别取样：优先使用**完整文件内容**；当本次读取窗口不是完整文件时，
    /// 重新读取整份文件（超过 MAX_TEXT_READ_SIZE 的超大文件只取头部）用于识别，
    /// 避免因窗口截断在多字节字符中间而误判编码。
    fn encoding_probe_bytes(
        path: &str,
        window_start: u64,
        window_truncated: bool,
        window: &[u8],
    ) -> Result<Vec<u8>, String> {
        // window 非空才算“本次窗口就是完整文件”；否则（如 length=0）空样本会被识别成 utf-8，
        // 让 GBK 文件也被报成 utf-8。
        if window_start == 0 && !window_truncated && !window.is_empty() {
            return Ok(window.to_vec());
        }
        let size = fs::metadata(path)
            .map_err(|e| format!("读取文件失败: {}", e))?
            .len();
        if size <= MAX_TEXT_READ_SIZE as u64 {
            let bytes = fs::read(path).map_err(|e| format!("读取文件失败: {}", e))?;
            Ok(Self::utf8_trim_incomplete_tail(&bytes).to_vec())
        } else {
            let mut f = File::open(path).map_err(|e| format!("打开文件失败: {}", e))?;
            let mut head = vec![0u8; MAX_TEXT_READ_SIZE];
            f.read_exact(&mut head)
                .map_err(|e| format!("读取文件失败: {}", e))?;
            Ok(Self::utf8_trim_incomplete_tail(&head).to_vec())
        }
    }

    /// 编码识别采样用：若切片唯一的问题是“尾部有一个不完整的多字节字符”，则截到最后一个完整字符；
    /// 存在真正非法字节时保持原样，交由识别逻辑判定为非 UTF-8 文本。
    fn utf8_trim_incomplete_tail(bytes: &[u8]) -> &[u8] {
        match std::str::from_utf8(bytes) {
            Ok(_) => bytes,
            Err(e) if e.error_len().is_none() => &bytes[..e.valid_up_to()],
            Err(_) => bytes,
        }
    }

    /// 沙箱比较用的路径键：规范化（去 `\\?\`、折叠 `.`/`..`）+ 小写。
    /// Windows 路径大小写不敏感，`F:\A` 与 `f:\a` 必须视为同一路径。
    fn sandbox_cmp_key(p: &std::path::Path) -> String {
        let s = normalize_path(p).to_string_lossy().into_owned();
        // 仅 Windows 路径大小写不敏感；类 Unix 保持大小写敏感，避免把两个不同路径误判为同一路径
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s
        }
    }

    /// 用"最长可 canonicalize 的前缀 + 未存在的尾部"拼出尽量真实的绝对路径。
    /// - 目标存在：等价于 canonicalize（大小写/短名/符号链接全部由 OS 解析）
    /// - 目标不存在（如新建文件）：定位到最近的存在祖先再拼回尾部，避免整段退回文本比较
    /// - 尾部含 `..` 等特殊段、或整条路径都不可解析：退回 normalize_path 的文本形式
    fn resolve_existing_prefix(p: &std::path::Path) -> std::path::PathBuf {
        use std::path::Component;
        let comps: Vec<Component> = p.components().collect();
        for split in (1..=comps.len()).rev() {
            let tail = &comps[split..];
            // 尾部只接受普通段：含 `..`/`.`/前缀段时换更短的 split，让它们进入可 canonicalize 的前缀
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

    /// 宽松解析 HEX 字符串：允许 0x 前缀与空格/冒号/逗号/短横线分隔（便于从 hex dump 直接粘贴）
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
        // 空内容视为 0 字节（是否允许由调用方决定：write_binary_file 的 replace 用它删除字节）
        if cleaned.is_empty() {
            return Ok(Vec::new());
        }
        if !cleaned.len().is_multiple_of(2) {
            return Err(format!(
                "长度为 {} 个十六进制字符（奇数），每字节需要两位",
                cleaned.len()
            ));
        }
        let bad: String = cleaned
            .chars()
            .filter(|c| !c.is_ascii_hexdigit())
            .collect();
        if !bad.is_empty() {
            return Err(format!("包含非法字符: [{}]，只允许 0-9, A-F, a-f", bad));
        }
        (0..cleaned.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .map_err(|e| format!("解析失败: {}", e))
            })
            .collect()
    }

    /// 取"待改范围"的实际字节 + 范围说明，用于 expected_hex 校验。
    /// 刻意不做 clamp 补齐：越界时返回偏短/空切片，从而必然判定为不匹配。
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
                (cur[start..].to_vec(), "文件末尾(追加点)".to_string())
            }
            "insert" => {
                let off = (offset.unwrap_or(0) as usize).min(cur.len());
                let end = off.saturating_add(expect_len).min(cur.len());
                (cur[off..end].to_vec(), format!("插入点 offset={}", off))
            }
            "replace" => {
                let off = offset.unwrap_or(0) as usize;
                let len = replace_length.unwrap_or(0);
                if off >= cur.len() {
                    return (Vec::new(), format!("[{}..{}) 越界", off, off.saturating_add(len)));
                }
                let end = off.saturating_add(len).min(cur.len());
                (cur[off..end].to_vec(), format!("[{}..{})", off, end))
            }
            _ => (cur.to_vec(), "整个文件".to_string()),
        }
    }

    /// HEX 预览：空格分隔的大写字节，超长截断，避免大范围刷屏
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
                "{} …（共 {} 字节，仅显示前 {} 字节）",
                shown.join(" "),
                bytes.len(),
                MAX_SHOW
            )
        } else {
            shown.join(" ")
        }
    }

    /// dry_run 预览：只输出变更窗口（限长）+ 前后大小与指纹，不写文件
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
            "[DRY-RUN] {} | {} | {}B→{}B | sha256:{}→{}\n未写入文件（去掉 dry_run 或传 dry_run=false 才执行）",
            path,
            action,
            old.len(),
            new.len(),
            Self::fingerprint_short_of_bytes(old),
            Self::fingerprint_short_of_bytes(new)
        );

        let Some(f) = first else {
            out.push_str("\n内容无变化");
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
            "\n差异窗口 [{}, {})：{} 字节不同{}",
            win_start,
            win_end,
            changed,
            if show_end < win_end {
                format!("（窗口过长，仅显示前 {} 字节）", MAX_SHOW)
            } else {
                String::new()
            }
        ));
        out.push_str(&format!(
            "\n  旧 @{:08X}: {}",
            win_start,
            Self::hex_preview(&take(old))
        ));
        out.push_str(&format!(
            "\n  新 @{:08X}: {}",
            win_start,
            Self::hex_preview(&take(new))
        ));
        out
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

    /// 校验并规范化编码名：UTF-32 不在 encoding_rs 里，由内置实现处理，需单独放行。
    fn canonical_encoding(name: &str) -> Result<&'static str, String> {
        match name.to_ascii_lowercase().as_str() {
            "utf-32le" => Ok("utf-32le"),
            "utf-32be" => Ok("utf-32be"),
            _ => Ok(Self::get_encoding(name)?.name()),
        }
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

        // 结构合法的 UTF-8 是强信号：只要 UTF-8 全量校验通过、且打分不低于 GBK（允许 GBK 领先 <=0.02 的
        // 噪声），就判 UTF-8 并且**高置信**。
        // 不能再用“两候选分数差足够大”当作确定性条件——像纯 ASCII 占多数的 UTF-8 源码，
        // 用 GBK 解同样通顺，两者打分都接近 1.0、差距极小，会被误报为“编码识别不确定”。
        // 只有 GBK 分数明显更高（领先 >0.02）时才考虑 GBK，且领先 >=0.1 才算高置信。
        let (best, best_score, confident) = if s_utf8.is_finite() && s_gbk <= s_utf8 + 0.02 {
            ("utf-8", s_utf8, true)
        } else {
            // 走到这里说明 s_gbk > s_utf8（含 s_utf8 为负无穷，即非法 UTF-8）
            ("gbk", s_gbk, s_gbk - s_utf8 >= 0.1)
        };

        // 两个候选都不像正常文本时，再试其他 CJK 编码，取分最高的一个（置信度标低）。
        // 这里同样只用样本打分，避免大文件为识别把整份内容按 4 种编码各解一遍。
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
            // 单字节编码（iso-8859-1/latin1、windows-125x、koi8-r 等）：任何偏移都是字符边界
            n if Self::is_single_byte_encoding(n) => true,
            // GBK/Big5 等双字节编码：从文件头按"ASCII 单字节 / 双字节字符"逐字符推进，
            // 看能否正好停在 off。
            // 不能从"最近的 ASCII 字节"起步：GBK 双字节的第二字节也可能落在 ASCII 范围
            // （0x40-0x7E），会把字符内部误当成边界，从而在字符中间插入、切断多字节字符。
            _ => {
                let mut pos = 0usize;
                while pos < off {
                    match Self::legacy_char_advance(encoding, bytes, pos) {
                        Some(next) => pos = next,
                        None => {
                            // 非法/孤立字节，无法可靠判定 → 放行（宁可不拦也不错拦）
                            return true;
                        }
                    }
                }
                pos == off
            }
        }
    }

    /// 把字节偏移向下取整到该编码的字符边界（仅处理边界可廉价判定的编码；无法判定时原样返回）。
    /// `byte_at_off`：偏移处首字节（调用方已读到窗口时传入），用于判断 UTF-8 是否正好落在边界。
    fn floor_char_boundary(encoding: &str, path: &str, off: u64, byte_at_off: Option<u8>) -> u64 {
        if off == 0 {
            return 0;
        }
        match encoding.to_ascii_lowercase().as_str() {
            "utf-16le" | "utf-16be" => off - (off % 2),
            "utf-32le" | "utf-32be" => off - (off % 4),
            "utf-8" => {
                // UTF-8 续字节形如 10xxxxxx；若 off 处就是首字节，则本就在边界上
                if let Some(b) = byte_at_off {
                    if (b & 0xC0) != 0x80 {
                        return off;
                    }
                }
                // 最多回看 3 字节，即可找到离 off 最近的非续字节位置
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
            // 单字节编码：每个字节就是一个字符，边界就是 off 本身
            n if Self::is_single_byte_encoding(n) => off,
            _ => {
                // GBK/Big5/GB18030 等：边界必须从文件头逐字符推进才能判定（O(off)）。
                // 偏移过大时不值得为此整读前缀，原样返回；否则读 [0, off+4) 后推进，
                // 找到 <= off 的最近边界（一个字符最多 4 字节，通常只需回退 1~3 字节）。
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

    /// 单字节 / 双字节（GB18030 含四字节）编码下“推进一个字符”，返回下一个字符的起始位置。
    /// 遇到非法或孤立字节返回 None（无法可靠判定边界）。
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

    /// 是否为单字节编码（iso-8859-1/latin1、windows-125x、koi8-r、macintosh 等）。
    /// 这类编码每个字节就是一个字符，任何偏移都是字符边界；
    /// 若误按 GBK 的双字节规则对齐，会把 offset=1 这种合法位置回退到 0（内容与定位都错）。
    fn is_single_byte_encoding(name: &str) -> bool {
        Self::get_encoding(name)
            .map(|e| e.is_single_byte())
            .unwrap_or(false)
    }

    /// 从文件开头统计到 `upto` 字节为止的换行数（分块读取，避免为大偏移分配整段前缀）。
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

    /// encoding 参数是否表示“自动识别”：未传 / 空串 / "auto" 都算。
    /// 三个读工具此前对空串处理不一致（read_text_file 当 auto、read_text_lines 报错、
    /// text_search 把文件全部 skip），现在统一走这里。
    fn encoding_is_auto(enc: Option<&str>) -> bool {
        enc.map_or(true, |e| e.is_empty() || e.eq_ignore_ascii_case("auto"))
    }

    /// 解析 encoding 参数，返回 (编码, 置信度)：
    /// "auto"/未指定时自动检测并给出置信度；显式指定即视为高置信。校验编码有效性。
    /// 低置信度意味着"GBK/UTF-8 难以区分"，读工具应提示 AI 显式指定 encoding
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
        // 调用方已持有完整内容时，无论大小都直接在内存里算（fingerprint_of_bytes 内部对大文件采样头尾），
        // 避免为了算指纹把大文件再读一遍盘
        if let Some(b) = bytes {
            if b.len() as u64 == size {
                return Some(Self::fingerprint_of_bytes(b));
            }
        }
        if size <= INLINE_MAX {
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

    /// 找出 needle 在 hay 中的所有（不重叠）出现位置，返回 (start, end) 字节区间。
    /// 两侧都是合法 UTF-8 时，匹配起点必然落在字符边界上，可安全用于切片。
    fn find_all(hay: &str, needle: &str) -> Vec<(usize, usize)> {
        if needle.is_empty() {
            return Vec::new();
        }
        hay.match_indices(needle)
            .map(|(i, m)| (i, i + m.len()))
            .collect()
    }

    /// 字节偏移对应的行号（1-based，用于把“命中在哪”讲清楚）
    fn line_of(hay: &str, offset: usize) -> usize {
        hay[..offset.min(hay.len())].matches('\n').count() + 1
    }

    /// 自动识别编码的“自洽性”校验：若判定的编码根本无法无损解码现有文件，
    /// 说明识别不可靠（典型：GBK 文件被误判成 UTF-8），此时继续写会把文件毁成乱码，直接拒绝。
    /// 显式指定 encoding 的路径无需调用（resolve_write_encoding 已保证与原文件一致）。
    fn check_encoding_lossless(encoding_name: &str, existing: &[u8]) -> Result<(), McpError> {
        // 大文件（> 8MB）只校验头部样本：整份解码对大文件纯属浪费 CPU，
        // 而编码特征在文件开头就已体现。切片须退到字符边界，否则半截字符会被
        // decode_file 当成非法字节，导致正常文件被误拒。
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
                    "自动识别的编码 [{}] 无法无损解码现有文件，编码判定不可靠，拒绝写入以免把文件写成乱码。\
                     请先用 read_text_file 确认真实编码，再显式传入 encoding 重新调用",
                    encoding_name
                ),
                None,
            ));
        }
        Ok(())
    }


    /// 统计文本文件行数（与 read_text_lines 同一口径：非空内容按 '\n' 切分，"a\nb\n" 记 3 行；空文件记 0）。
    /// 编码无法识别或含非法字节时返回 None（调用方显示 "-"），不做猜测。
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
        } else if lower == "utf-32le" || lower == "utf-32be" {
            // encoding_rs 不支持 UTF-32，这里同样自行解码（与 encode 严格对称）
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
                return Err(format!("使用 {} 解码失败，数据可能包含无效字节", encoding_name));
            }
            (cow.into_owned(), false)
        };
        // 单次遍历同时统计 \n 与 \r\n（结果与两次 matches 完全一致），
        // 避免对大文件做两次全量字符串扫描
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

    /// UTF-32 解码：按字节序组装 u32 码点（encoding_rs 不支持 UTF-32，故自行实现）
    fn decode_utf32(body: &[u8], little_endian: bool) -> Result<String, String> {
        if body.len() % 4 != 0 {
            return Err("UTF-32 数据字节数不是 4 的倍数，无法解码（文件可能被截断）".to_string());
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
                None => return Err(format!("UTF-32 解码失败：0x{:08X} 不是有效码点", v)),
            }
        }
        Ok(out)
    }

    /// UTF-32 编码：按字节序写出 u32 码点（不含 BOM，BOM 由 encode_file 依原文件补回）
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

    /// 按编码把字符串编码为字节（不含 BOM）
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

    /// 备份 key 归一化：必须先转成**规范化绝对路径**再归一，原因有二：
    /// 1) resolve_path 现在回显相对路径，直接对相对路径取 key 会让同一文件的相对/绝对写法
    ///    落到不同备份分区（manage_backups/undo 就会找不到）；
    /// 2) 历史版本的 key 就是"绝对路径去 \\?\ 前缀（Windows 下再小写）"，保持一致才能继续找到旧备份。
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
        existing: Option<&[u8]>,
    ) -> Result<(), McpError> {
        let Some(exp) = expected_old else {
            return Ok(());
        };
        // 复用调用方已读到的字节，避免同一文件被重复读盘；未提供时才回退读盘
        let owned;
        let bytes: &[u8] = match existing {
            Some(b) => b,
            None => {
                if !std::path::Path::new(path).exists() {
                    return Err(e_param(
                        format!(
                            "文件不存在: {}。已提供 expected_old 说明期望文件存在，请核对路径",
                            path
                        ),
                        None,
                    ));
                }
                owned = fs::read(path)
                    .map_err(|e| e_internal(format!("读取文件失败: {}", e), None))?;
                &owned
            }
        };

        // 统一解码入口（剥离 BOM），保证与写入时的内容口径一致
        let actual_content = Self::decode_file(bytes, encoding_name)
            .map_err(|e| e_internal(e, None))?
            .content;

        // CRLF 归一化：read_text_lines 读取时已去除行尾 \r，比较前统一归一避免误拒。
        // 用 Cow：绝大多数内容不含 \r，此时零分配（旧实现每次比较都复制整份字符串）
        fn norm(s: &str) -> std::borrow::Cow<'_, str> {
            if s.contains('\r') {
                std::borrow::Cow::Owned(s.replace("\r\n", "\n"))
            } else {
                std::borrow::Cow::Borrowed(s)
            }
        }

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
                // offset 是**含 BOM 的文件原始字节偏移**，与写入路径同一基准；
                // 必须直接在原始字节上取窗口——用解码后 String 的 UTF-8 下标会在
                // 带 BOM（整体错 3 字节）以及 GBK/UTF-16（下标空间完全不同）时错位。
                let off = offset.unwrap_or(0) as usize;
                let bom_len = Self::detect_bom(bytes).len();
                if off < bom_len {
                    return Err(e_param(
                        format!(
                            "插入点 offset={} 落在文件 BOM 内（BOM 占 {} 字节，插入会破坏编码）。请改用 offset>={}",
                            off, bom_len, bom_len
                        ),
                        None,
                    ));
                }
                let off_c = off.min(bytes.len());
                if !Self::is_char_boundary(encoding_name, bytes, off_c) {
                    return Err(e_param(
                        format!(
                            "插入点 offset={} 不在 {} 的字符边界上（会切断多字节字符）",
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
                (norm(&window) == norm(exp), format!("插入点 offset={}", off), shown)
            }
            _ => {
                // 大文件只回头尾摘要，避免把整份（可能含敏感信息）内容回显出去
                (
                    norm(&actual_content) == norm(exp),
                    "整个文件".to_string(),
                    Self::clip_guard_preview(&actual_content),
                )
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

    /// 守卫校验失败时回显的"当前内容"预览：
    /// 内容不长则原样返回；过长只保留头尾并附长度与指纹，避免整份文件被回显（大文件刷屏 / 敏感内容外泄）
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
            "{}\n…（中间省略 {} 字符；全文共 {} 字符；内容指纹(非文件 sha256，勿用作 expected_sha256):{})…\n{}",
            head,
            chars.len() - PREVIEW_HEAD - PREVIEW_TAIL,
            chars.len(),
            Self::fingerprint_short_of_bytes(content.as_bytes()),
            tail
        )
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
                        "编码不一致，拒绝写入！文件 {} 的实际编码是 [{}]，但你指定的编码是 [{}]。直接写入会导致编码混乱。\n\
                         请改用 encoding='{}' 保持原编码后重新调用",
                        path, act, rn, act
                    ),
                    None,
                ))
            }
        }
    }

    /// 递归收集目录下待搜索的文件路径
    /// - include：任一 glob 命中才收录（同时按文件名与相对根路径匹配）
    /// - exclude：任一 glob 命中则跳过；命中目录时整棵剪枝
    /// - stat：记录过滤/剪枝/截断情况，供输出向调用方解释"搜到了什么、为什么没搜全"
    fn collect_files(
        dir: &std::path::Path,
        root: &std::path::Path,
        ext_filter: &[String],
        include: &Option<Vec<GlobMatcher>>,
        exclude: &Option<Vec<GlobMatcher>>,
        recursive: bool,
        skip_hidden: bool,
        max_files: usize,
        files: &mut Vec<String>,
        stat: &mut SearchScanStat,
    ) -> Result<(), String> {
        let entries = fs::read_dir(dir)
            .map_err(|e| format!("无法读取目录 {}: {}", dir.display(), e))?;

        let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        sorted.sort_by_cached_key(|e| e.file_name());

        for entry in sorted {
            if files.len() >= max_files {
                stat.capped = true;
                return Ok(());
            }

            // 跳过本工具自己产生的备份目录 / 临时文件 / 锁文件
            let name = entry.file_name().to_string_lossy().to_string();
            if is_internal_file(&name) {
                continue;
            }

            let entry_path = entry.path();
            // 相对搜索根的路径（统一 / 分隔），供 "src/**/*.rs" 这类 glob 匹配
            let rel = entry_path
                .strip_prefix(root)
                .unwrap_or(entry_path.as_path())
                .to_string_lossy()
                .replace('\\', "/");

            let file_type = entry.file_type().ok();
            let is_dir = file_type.as_ref().map(|ft| ft.is_dir()).unwrap_or(false);
            let is_file = file_type.as_ref().map(|ft| ft.is_file()).unwrap_or(false);

            // 隐藏项（以 . 开头，如 .git/.env）默认跳过；若 include 显式点名则放行
            let hidden = skip_hidden
                && name.starts_with('.')
                && !Self::glob_match_any(&name, &rel, include);

            if is_dir {
                // exclude 命中目录时整棵剪枝，不再递归进去（如 "node_modules/**"）
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
                        max_files, files, stat,
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

    /// glob 命中判断：同时按文件名与相对路径匹配
    /// （"*.rs" 命中文件名，"src/**/*.rs" 命中相对路径）
    fn glob_match_any(name: &str, rel: &str, matchers: &Option<Vec<GlobMatcher>>) -> bool {
        match matchers {
            None => false,
            Some(ms) => ms.iter().any(|m| m.is_match(name) || m.is_match(rel)),
        }
    }

    /// 目录是否被 exclude 命中：额外按 "{rel}/子项" 再试一次，
    /// 使 "node_modules/**"、"**/dist/**" 这类写法也能剪掉目录本身
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

    /// 编译 glob 列表；空列表等同于未设置
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
                        e_param(format!("{} 的 glob 表达式 '{}' 非法: {}", field, it, e), None)
                    })?;
                    out.push(g.compile_matcher());
                }
                Ok(Some(out))
            }
        }
    }

    /// 读取待搜索文件并解码，返回 (生效编码名, 内容, 原始字节)；失败时给出可读原因（不再静默跳过）。
    /// 指纹由调用方在“确有命中”时再算，避免为不命中的候选文件白做一次全量哈希。
    fn read_search_content(
        file_path: &str,
        encoding_raw: Option<&str>,
        encoding_auto: bool,
    ) -> Result<(String, String, Vec<u8>), String> {
        // 先看大小再读：超限文件不必整份读进内存（返回文案与过去一致）
        let size = fs::metadata(file_path)
            .map_err(|e| format!("读取失败: {}", e))?
            .len();
        if size > MAX_REGEX_FILE_SIZE {
            return Err(format!(
                "文件过大({}B > {}B)，已跳过",
                size, MAX_REGEX_FILE_SIZE
            ));
        }
        let bytes = fs::read(file_path).map_err(|e| format!("读取失败: {}", e))?;
        if encoding_auto {
            let detected = Self::detect_encoding(&bytes);
            // 自动识别的编码若仍有非法字节，退化为宽松解码（U+FFFD 替换）而不是跳过整个文件，
            // 以免目录搜索漏文件；显式指定 encoding 时仍严格报错。
            // 统一走 decode_file：UTF-16/UTF-32 由内置实现处理（encoding_rs 不支持 UTF-32），
            // 并顺带剥掉 BOM，避免 BOM 字符混进搜索结果。
            let content = match Self::decode_file(&bytes, detected) {
                Ok(ft) => ft.content,
                // 宽松兜底：编码不在 encoding_rs 里或含非法字节时用替换式解码，避免整份文件被跳过
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
                        "不是有效的 UTF-8 文本（可指定 encoding=\"auto\" 或显式编码，如 gbk）"
                            .to_string(),
                    ),
                }
            } else {
                // 同样走 decode_file：显式指定 utf-16/utf-32 也能搜索
                let content = Self::decode_file(&bytes, name)
                    .map_err(|e| format!("按 {} 解码失败({})", name, e))?
                    .content;
                Ok((name.to_string(), content, bytes))
            }
        }
    }

    /// 搜索结果里展示的单行文本：超长时截断，避免一行刷屏（保留原文缩进，可直接作为 expected_old）
    fn clip_line(line: &str) -> String {
        const MAX_SEARCH_LINE_LEN: usize = 300;
        let chars: Vec<char> = line.chars().collect();
        if chars.len() <= MAX_SEARCH_LINE_LEN {
            line.to_string()
        } else {
            let head: String = chars[..MAX_SEARCH_LINE_LEN].iter().collect();
            format!("{}…(该行共 {} 字符，已截断)", head, chars.len())
        }
    }
}

#[tool_router]
impl FileIoServer {
    /// 读取文本文件
    #[tool(
        name = "read_text_file",
        description = "按字节读文本片段(offset/length，默认最多 10MB，length 须≥1)。返回头: 路径|编码(BOM标注)|大小|sha256|区间。默认会为对齐字符边界微调区间(返回头会标注)，需要精确字节区间就传 strict=true；要按行编辑请用 read_text_lines",
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

        let mut start = params.offset.unwrap_or(0);

        // length=0 没有“合理语义”（既不是读空也不是读全部），明确拒绝而不是各人各解释
        if params.length == Some(0) {
            return Err(e_param(
                "length 必须 ≥1。只想要大小/指纹请用 file_info；想读全部请省略 length",
                None,
            ));
        }
        // strict=true：length/offset 精确生效（不做“至少读 4 字节”、不对 offset 下取整），
        // 需要精确分页/按字节对齐时用它；否则 length 只是提示值，实际区间可能被调整（返回头会标注）。
        let strict = params.strict.unwrap_or(false);

        // 允许 offset=0 读空文件（返回空内容）；仅当偏移越过文件末尾才报错
        if start > 0 && start >= file_size {
            return Err(e_param(
                format!("offset={} 超出文件范围（文件共 {}B）", start, file_size),
                None,
            ));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;

        // 硬上限：length 传得再大也不一次读入超过 MAX_READ_HARD_LIMIT，避免内存/响应失控
        let max_len = params
            .length
            .unwrap_or(MAX_TEXT_READ_SIZE)
            .min(MAX_READ_HARD_LIMIT);
        let room = (file_size - start) as usize;
        // 非 strict 下 length 是提示值：至少读 4 字节，保证窗口能覆盖一个完整多字节字符，
        // 否则 length 过小时分页会卡住不前进；strict 下严格按 length 读。
        let mut read_len = if strict {
            max_len.min(room)
        } else {
            max_len.min(room).max(room.min(4))
        };
        // 已到文件末尾（room=0）不算“被截断”，否则会误报截断告警
        let mut truncated = read_len < room && read_len > 0;
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| e_internal(format!("读取失败: {}", e), None))?;

        // 编码决策：显式指定则直接采用；auto/未指定时始终基于**完整文件**识别编码，
        // 不能用本次读取窗口——窗口可能从多字节字符中间开始/结束，会让 UTF-8 校验失败而误判成 GBK。
        let requested_enc = params.encoding.as_deref();
        let auto_detect = Self::encoding_is_auto(requested_enc);
        let (encoding_name, enc_confident) = if auto_detect {
            let probe = Self::encoding_probe_bytes(&params.path, start, truncated, &buffer)
                .map_err(|e| e_internal(e, None))?;
            Self::detect_encoding_with_confidence(&probe)
        } else {
            // 走 canonical_encoding：UTF-32 不在 encoding_rs 里，显式指定时也必须能通过
            (
                Self::canonical_encoding(requested_enc.unwrap_or("utf-8"))
                    .map_err(|e| e_param(e, None))?,
                true,
            )
        };
        // offset 可能落在多字节字符中间（按 read_len 分页时几乎必然如此）。向下取整到字符边界，
        // 否则从“半个字符”开始解码会得到非法字节错误，导致分页读 UTF-8 文件从第二页起必然失败。
        // strict 模式不做这个回退（调用方要的是精确区间），改由后面的“丢弃边缘不完整字节”兜底。
        let aligned = if strict {
            start
        } else {
            Self::floor_char_boundary(encoding_name, &params.path, start, buffer.first().copied())
        };
        let align_note = if aligned != start {
            start = aligned;
            file.seek(SeekFrom::Start(start))
                .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;
            let remaining = (file_size - start) as usize;
            read_len = if strict {
                max_len.min(remaining)
            } else {
                max_len.min(remaining).max(remaining.min(4))
            };
            truncated = read_len < remaining && read_len > 0;
            buffer = vec![0u8; read_len];
            file.read_exact(&mut buffer)
                .map_err(|e| e_internal(format!("读取失败: {}", e), None))?;
            format!(" ⚠️offset 已下取整到字符边界 {}", start)
        } else {
            String::new()
        };

        // 行号前缀统计放在边界对齐之后，保证显示的行号与最终 start 一致
        let prefix_line_count = if show_ln && start > 0 {
            Self::count_newlines_before(&mut file, start)
                .map_err(|e| e_internal(format!("读取前缀失败: {}", e), None))?
        } else {
            0
        };

        // 从 offset=0 开始读取时，头部可能带 BOM，需剥离并返回给 AI 可见的编码名
        let bom = if start == 0 { Self::detect_bom(&buffer) } else { &[][..] };
        // strict 模式的窗口起点可能正好切在字符中间：丢弃起始处不完整的字节
        // （UTF-8 的续字节形如 10xxxxxx，最多 3 个；其他编码无法廉价判定，会在解码失败时报错）
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
            " ⚠️编码识别不确定(GBK/UTF-8 难以区分)，建议显式指定 encoding 后重新读取".to_string()
        };

        // 只解码本次读取的窗口。窗口按字节截断，尾部可能是“半个多字节字符”，
        // 这属于正常截断而非文件损坏：截断时容忍尾部不完整序列，避免整次读取直接报错。
        // consumed 记录窗口内“真正构成完整字符”的字节数，用于把返回区间右端也对齐到字符边界。
        // strict 模式同样要容忍边缘（它本来就可能切在字符中间），另用 edge_note 告知。
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
                            "文件不是有效的 UTF-8 编码（从偏移量 {} 起读取的 {} 字节内包含非法字节），请尝试指定正确的 encoding 参数",
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
            // encoding_rs 不支持 UTF-32：按 4 字节对齐裁掉尾部不完整码元后走内置解码
            let mut end = body.len();
            if tolerate_edges {
                end -= end % 4;
            }
            consumed = end;
            Self::decode_utf32(&body[..end], encoding_name.eq_ignore_ascii_case("utf-32le"))
                .map_err(|e| e_internal(e, None))?
        } else if tolerate_edges {
            // 双字节/多字节编码同理：尾部可能截断在字符中间，逐字节回退（最多 4 字节）再试
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
                            "按 {} 解码失败（偏移量 {} 起的窗口内包含无效字节）。\
                             若是为按字节精确分页（strict=true）而切在了字符中间，去掉 strict 即会自动对齐到字符边界",
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
        // 返回区间右端：start + BOM + 实际消费的完整字符字节数（保证落在字符边界上）
        let end_off = start + bom.len() as u64 + consumed as u64;

        // strict 模式丢弃了边缘不完整字节时明确告知（非 strict 的尾部容忍已体现在区间右端/已截断告警）
        let edge_note = if strict && (lead_skip > 0 || consumed < body.len()) {
            format!(
                " ⚠️strict：为落在字符边界已丢弃边缘不完整字节 {}B（实际返回 [{},{})；要去掉该行为请省略 strict）",
                lead_skip + (body.len() - consumed),
                start,
                end_off
            )
        } else {
            String::new()
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
            content
        };

        let trunc_warn = if truncated {
            format!(
                " ⚠️已截断: 文件共 {}B，仅返回 [{},{})。若要完整编辑请改用 read_text_lines，或用 offset 分页读取剩余部分",
                file_size, start, end_off
            )
        } else {
            String::new()
        };

        // 版本指纹（供后续写入时作为 expected_sha256 回传，防止并发改动被覆盖）。
        // 大文件用采样指纹，避免"只读一小段却要把整个大文件再读一遍算 sha"。
        // 判据必须是“buffer 确实覆盖了整文件”，不能用 !truncated：length=0 时 truncated 为 false
        // 但 buffer 为空，会把空串哈希当成文件指纹（AI 回传后必然 E_EXTERNAL_CHANGED 假报错）。
        // 注意：必须用完整 buffer（含 BOM），不能用剥离 BOM 后的 body，否则指纹与实际文件不符。
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
        // 先校验模式，避免未知 mode 也走完建目录/写前校验等副作用
        if !matches!(mode, "overwrite" | "append" | "insert") {
            return Err(e_param(
                format!("不支持的模式: {}，可选: overwrite, append, insert", mode),
                None,
            ));
        }

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

        // 编码自洽性校验（仅走自动识别的路径）：判定出的编码若无法无损解码现有文件，
        // 说明识别不可靠（典型：GBK 文件被误判成 UTF-8），继续写可能把文件毁成乱码，直接拒绝。
        // 显式指定 encoding 时由 resolve_write_encoding 保证与原文件一致，无需重复校验。
        // （与 edit_file_sections 共用同一实现，避免两处逻辑漂移）
        if Self::encoding_is_auto(params.encoding.as_deref()) {
            if let Some(b) = existing_bytes.as_deref() {
                Self::check_encoding_lossless(encoding_name, b)?;
            }
        }

        // 按指定编码将内容转换为字节（不含 BOM；BOM 仅 overwrite 时补在文件头）
        let bytes: Vec<u8> = Self::encode_content(encoding_name, &params.content)
            .map_err(|e| e_internal(e, None))?;

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| e_internal(e, None))?;

        // 写前校验（按 mode 校验“当前想改范围”的内容）：防止未确认当前内容就误写；
        // 复用上面已读到的 existing_bytes，避免同一文件被重复读盘
        Self::check_write_guard(
            &params.path,
            encoding_name,
            mode,
            params.offset,
            params.expected_old.as_deref(),
            existing_bytes.as_deref(),
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
                    // 与真实写入一致：新建文件要先补默认 BOM，否则 preview 的预计 sha 会与落盘不符
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
                                "insert 模式需要文件已存在，但文件不存在: {}. 请使用 overwrite 模式创建新文件",
                                params.path
                            ),
                            None,
                        )
                    })?;
                    let off = (params.offset.unwrap_or(0) as usize).min(original.len());
                    if off < bom.len() {
                        return Err(e_param(
                            format!(
                                "insert 的 offset={} 落在文件 BOM 内（BOM 占 {} 字节，插入会破坏编码）。请改用 offset>={}",
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
                // append 是"就地追加"，硬链接备份会跟着变，因此不做备份（可回滚性由 OCC + 原子写覆盖其他模式）。
                // 新建文件时（existing 为空）必须先补默认 BOM，否则 UTF-16/32 会写成“无 BOM”而被下次误判成 GBK。
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
                .map_err(|e| e_internal(format!("E_WRITE 追加失败: {}", e), None))?;
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
                        format!("insert 模式需要文件已存在，但文件不存在: {}. 请使用 overwrite 模式创建新文件", params.path),
                        None,
                    )
                })?;
                let off = off.min(original.len());
                // offset 是含 BOM 的原始字节偏移：落在 BOM 内会把新内容插到 BOM 之前/中间，直接破坏编码
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
            _ => Err(e_param(
                format!("不支持的模式: {}，可选: overwrite, append, insert", mode),
                None,
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
        // 整份读入内存 + 解码会带来 2~3 倍内存放大，设上限避免超大文件把内存吃满；
        // 需要读大文件请改用 read_text_file（支持 offset/length 分页）。
        // 注意保持与 fs::read 一致的错误码：文件不存在仍是 E_NOT_FOUND，不要退化成 E_READ
        let size = match fs::metadata(&params.path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(e_internal(format!("文件不存在: {}", params.path), None));
            }
            Err(e) => return Err(e_internal(format!("无法获取文件信息: {}", e), None)),
        };
        if size > MAX_TEXT_LINES_FILE_SIZE {
            return Err(e_param(
                format!(
                    "文件过大({}B > {}B)，read_text_lines 会整份读入内存。请改用 read_text_file 的 offset/length 分页读取",
                    size, MAX_TEXT_LINES_FILE_SIZE
                ),
                None,
            ));
        }
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
            params.encoding.as_deref(),
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
        // 允许 offset=0 读空文件（返回空内容）；仅当偏移越过文件末尾才报错
        if start > 0 && start >= file_size {
            return Err(e_param(
                format!("offset={} 超出文件范围（文件共 {}B）", start, file_size),
                None,
            ));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| e_internal(format!("Seek 失败: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        // 硬上限：HEX dump 体积约为原字节的 4~5 倍，不加限制会把响应撑爆
        let read_len = params
            .length
            .unwrap_or(remaining)
            .min(remaining)
            .min(MAX_BINARY_DUMP_LIMIT);
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

        // 本次读取覆盖整个文件时（offset=0 且读满）可直接复用已读 buffer 算指纹，
        // 省掉 path_fingerprint_short 的重新读盘；部分读取时仍需按路径读盘。
        let sha = if start == 0 && read_len as u64 == file_size {
            Self::fingerprint_short_of_bytes(&buffer)
        } else {
            Self::path_fingerprint_short(&params.path)
        };

        // 4MB 硬上限造成的截断必须显式告知，否则调用方会按返回长度误判文件大小
        let trunc_warn = if (read_len as u64) < remaining as u64 {
            format!(
                " ⚠️已截断: 文件共 {}B（offset {} 起剩余 {}B），单次最多 dump {}B；请用 offset 分页读取剩余部分",
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
        description = "按十六进制写二进制。mode=overwrite(默认)/append/insert(offset)/replace(offset+replace_length)。\
replace/insert 的 offset 越界会直接报错（不再静默截断）；建议传 expected_hex 校验待改位置的原始字节（offset 算错时兜底）；\
dry_run=true 只返回 HEX diff 预览不落盘",
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
        if !matches!(mode, "overwrite" | "append" | "insert" | "replace") {
            return Err(e_param(
                format!("不支持的模式: {}，可选: overwrite, append, insert, replace", mode),
                None,
            ));
        }
        let dry_run = params.dry_run.unwrap_or(false);
        // 与 expected_hex 使用同一套宽松解析：支持 0x/0X 前缀与空格/冒号等分隔符。
        // 空内容 = 0 字节：只有 replace 天然需要“删除字节”语义，其余模式多为笔误
        let bytes = Self::parse_hex_flexible(&params.hex_data)
            .map_err(|e| e_param(format!("hex_data 解析失败: {}", e), None))?;
        if bytes.is_empty() {
            match mode {
                // replace 用空内容删除字节，属正常用法
                "replace" => {}
                "overwrite" => {
                    // overwrite 会把文件清空为 0 字节，必须显式确认（expected_hex 是 OCC 校验，
                    // 在 overwrite 下需要贴出全文 hex 才能通过，不适合当确认开关）
                    if !params.confirm.unwrap_or(false) {
                        return Err(e_param(
                            "hex_data 为空，overwrite 会把文件清空为 0 字节。确需清空请传 confirm=true",
                            None,
                        ));
                    }
                }
                _ => {
                    return Err(e_param(
                        format!(
                            "hex_data 为空，mode={} 下不会改动任何内容（静默空操作）。请提供要写入的 HEX；若确实不想写入，跳过本次调用即可",
                            mode
                        ),
                        None,
                    ));
                }
            }
        }

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

        // 写前比对"待改范围"的实际字节：二进制没有行号/锚点，offset 算错只能靠这个兜住
        if let Some(exp_hex) = params.expected_hex.as_deref() {
            // 空 expected_hex = “不校验”，却会让人以为已经校验过（0 字节永远匹配）→ 明确拒绝
            if exp_hex.trim().is_empty() {
                return Err(e_param(
                    "expected_hex 不能为空：空串等于没有校验。不需要校验就整个省略该参数",
                    None,
                ));
            }
            let expected = Self::parse_hex_flexible(exp_hex)
                .map_err(|e| e_param(format!("expected_hex 解析失败: {}", e), None))?;
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
                        "expected_hex 校验不通过：待改范围的原始字节与期望不一致（offset/replace_length 可能算错）。\n\
                         === 范围[{}]实际字节:\n{}\n=== 你给的期望字节:\n{}",
                        scope,
                        Self::hex_preview(&actual),
                        Self::hex_preview(&expected)
                    ),
                    None,
                ));
            }
        }

        // 先算出"改后字节"：真实写入与 dry_run 预览共用同一套逻辑，避免两处不一致
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
                            "insert 的 offset={} 超出文件大小 {}B；请先用 read_binary_file 确认真实长度后重试",
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
                        format!("replace 的 offset={} 超出文件大小 {}B", off, current.len()),
                        None,
                    ));
                }
                // checked_add 防止 offset + replace_length 溢出后绕过越界校验
                let end = match off.checked_add(replace_len) {
                    Some(end) if end <= current.len() => end,
                    _ => {
                        return Err(e_param(
                            format!(
                                "replace 范围越界：offset={} + replace_length={} 超出文件大小 {}B。\
                                 请核对偏移（可用 read_binary_file 查看真实内容），或调小 replace_length",
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
                return Err(e_param(format!("不支持的模式: {}", other), None));
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
                    .map_err(|e| e_internal(format!("E_WRITE 写入失败: {}", e), None))?;
                let mut tail = String::new();
                if let Some(h) = &bak {
                    Self::finish_backup(h, &new_data);
                    tail = " | undoable".to_string();
                }
                Ok(format!("OK {} | {}B | sha256:{}{}", params.path, new_data.len(), Self::fingerprint_short_of_bytes(&new_data), tail))
            }
            // 追加仍走 O_APPEND（避免大文件整份重写）；new_data 只用于指纹
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
                .map_err(|e| e_internal(format!("E_WRITE 追加失败: {}", e), None))?;
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
                let bak = Self::backup_before_write(
                    &params.path,
                    "write_binary_file:replace",
                    Some(&current),
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
                    replace_len,
                    bytes.len(),
                    off,
                    new_data.len(),
                    Self::fingerprint_short_of_bytes(&new_data),
                    tail
                ))
            }
            other => Err(e_param(format!("不支持的模式: {}", other), None)),
        }
        })
    }

    /// 搜索文件/目录中的文本内容(正则)
    #[tool(
        name = "text_search",
        description = "在文件/目录中搜索文本。mode=regex(默认，正则)/literal(普通文本，pattern 无需转义)。\
结果按文件分组(含 sha256，可直接用于 edit_file_lines 的 expected_sha256)，每条 行号:列:[命中片段] \"整行原文\"。\
目录默认递归并自动跳过隐藏文件/目录(.git/.env 等，skip_hidden=false 可关)，可用 include/exclude(glob)、\
extension/extensions、max_files 控制范围；encoding 默认 auto(逐文件识别，可区分 GBK/UTF-8)；context_lines>0 附带上下文行",
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
        let max_results = params.max_results.unwrap_or(100).max(1);
        let recursive = params.recursive.unwrap_or(true);
        let context_lines = params.context_lines.unwrap_or(0);
        let skip_hidden = params.skip_hidden.unwrap_or(true);
        // 默认 regex（保持既有行为）；literal 时把 pattern 当普通文本
        let literal = match params.mode.as_deref() {
            None | Some("") => false,
            Some(m) if m.eq_ignore_ascii_case("literal") => true,
            Some(m) if m.eq_ignore_ascii_case("regex") => false,
            Some(m) => {
                return Err(e_param(
                    format!("不支持的 mode: {}，可选: regex(默认), literal", m),
                    None,
                ))
            }
        };
        // 空 pattern 会匹配每行的每个位置（产生大量无意义命中），直接拒绝
        if params.pattern.is_empty() {
            return Err(e_param(
                "pattern 不能为空；请给出要搜索的文本或正则".to_string(),
                None,
            ));
        }
        // 默认 auto：与 read_text_file 一致，逐文件自动识别编码（可区分 GBK/UTF-8）
        let encoding_raw = params.encoding.as_deref();
        let encoding_auto = Self::encoding_is_auto(encoding_raw);

        // literal 模式转义正则元字符：AI 常直接传含 . * [ 的普通文本，避免被当正则误匹配
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
            e_param(format!("正则表达式错误: {}", e), None)
        })?;

        // 后缀过滤（去掉可能的 . 前缀；extension 与 extensions 可混用，取并集）
        let mut ext_list: Vec<String> = Vec::new();
        for e in params.extension.iter().chain(
            params.extensions.iter().flatten(),
        ) {
            let e = e.trim_start_matches('.').to_lowercase();
            if !e.is_empty() && !ext_list.contains(&e) {
                ext_list.push(e);
            }
        }
        // 目录模式下的范围过滤：include(白名单) / exclude(黑名单)，均为 glob
        let include = Self::compile_globs(&params.include, "include")?;
        let exclude = Self::compile_globs(&params.exclude, "exclude")?;

        let path = std::path::Path::new(&params.path);
        let is_dir = path.is_dir();

        // 收集需要搜索的文件列表（文件数上限独立控制，达到上限会被明确告警而不是静默吞掉）
        let max_files = params.max_files.unwrap_or(max_results * 10).max(1);
        let mut files: Vec<String> = Vec::new();
        let mut scan = SearchScanStat::default();
        if is_dir {
            Self::collect_files(
                path, path, &ext_list, &include, &exclude, recursive, skip_hidden, max_files,
                &mut files, &mut scan,
            )
            .map_err(|e| e_internal(e, None))?;
        } else {
            files.push(params.path.clone());
        }

        let mut blocks: Vec<String> = Vec::new();   // 每个命中文件一个输出块
        let mut stored = 0usize;                    // 已返回的命中条数
        let mut found = 0usize;                     // 已读取文件内的全部命中数（可能多于 stored）
        let mut searched_files = 0usize;
        let mut matched_files = 0usize;
        let mut skipped: Vec<String> = Vec::new();  // 读/解码失败的文件及原因

        for file_path in &files {
            if stored >= max_results {
                break;
            }
            searched_files += 1;

            // 读取 + 解码（失败不再静默跳过，统一计入 skipped 以便调用方排查）
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
            // 达到 max_results 后不再存储，但继续计数，便于给出真实命中总量。
            // 直接流式遍历 content.lines()，不再为首个命中就收集整份行向量（大文件省内存）
            let mut hits: Vec<Hit<'_>> = Vec::new();
            for (line_idx, line) in content.lines().enumerate() {
                for mat in re.find_iter(line) {
                    found += 1;
                    if stored + hits.len() >= max_results {
                        continue;
                    }
                    // 列号按字符数计（原按字节偏移，中文行会错位）
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

            // 文件块头带上 sha256，可直接回传给 edit_file_lines 的 expected_sha256。
            // 指纹只在“确有命中”时才计算：不命中的候选文件不做无谓的全量哈希。
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
                // 上下文模式需要按下标访问相邻行，这时才收集行向量
                let lines: Vec<&str> = content.lines().collect();
                // 合并相邻的上下文区间，同一行只输出一次
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
                "⚠️ 命中过多：仅返回前 {} 条（已扫描范围内共 {} 处匹配）。可提高 max_results，或收窄 include/exclude/extension 后重试",
                stored, found
            ));
        }
        if scan.capped {
            warnings.push(format!(
                "⚠️ 候选文件已达上限 {}，目录可能未完全覆盖（已收集 {} 个；另有 {} 个候选因 include/exclude/后缀/隐藏被过滤，未计入收集上限）。可提高 max_files 或收窄范围后重试",
                max_files, files.len(), scan.filtered
            ));
        }
        if !skipped.is_empty() {
            let shown: Vec<String> = skipped.iter().take(5).cloned().collect();
            warnings.push(format!(
                "⚠️ {} 个文件未能搜索：{}\n   （常见原因：二进制/非文本内容、文件过大，或与显式指定的 encoding 不匹配；可换用正确的 encoding 重试）",
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
            out.push_str("\n（无匹配）");
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

    /// 批量原子片段编辑：一次调用完成多处“精确文本 → 新文本”替换
    #[tool(
        name = "edit_file_sections",
        description = "批量精确替换(一次调用改多处，默认全成或全不成)：edits=[{expected_old, content, occurrence?}]。\
expected_old 须与原文逐字符一致(含缩进/空行，读到的换行是 CRLF 也可写成 LF)且默认要求全文唯一，命中多处时用 occurrence 指定第几处；\
content 传空串=删除该片段；所有片段基于同一次快照定位，重叠会报错；支持 expected_sha256 防并发覆盖、dry_run 预览 diff。\
（多处互不相邻的修改优先用它：比 edit_file_lines 少算行号、比 regex_replace 不需转义）",
        annotations(title = "批量片段编辑", destructive_hint = true)
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
                "edits 不能为空：请至少提供一条 {expected_old, content}",
                None,
            ));
        }

        // 与 regex_replace 同一保护：整份读入内存后重建，过大文件应先分割
        let file_size = fs::metadata(&params.path)
            .map_err(|e| e_internal(format!("无法获取文件信息: {}", e), None))?
            .len();
        if file_size > MAX_REGEX_FILE_SIZE {
            return Err(e_param(
                format!(
                    "文件过大 ({}B)，最大支持 {}B。如需处理大文件，请先手动分割后操作",
                    file_size, MAX_REGEX_FILE_SIZE
                ),
                None,
            ));
        }

        let all_or_nothing = params.all_or_nothing.unwrap_or(true);
        self.with_path_lock(&params.path, || {
            let bytes = fs::read(&params.path)
                .map_err(|e| e_internal(format!("读取文件失败: {}", e), None))?;
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

            // ---- 第一步：所有片段都在**原文快照**上定位，而不是“改一个再找下一个” ----
            let mut planned: Vec<(usize, usize, String, usize)> = Vec::new();
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
                let hits = Self::find_all(&hay, &needle);
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
                                 请把 expected_old 写得更长以唯一定位，或用 occurrence 指定第几处",
                                idx, n, spots.join("、"), more
                            ));
                            continue;
                        }
                    },
                };
                match chosen {
                    Some((s, e)) => planned.push((s, e, op.content.replace("\r\n", "\n"), idx)),
                    None => problems.push(format!(
                        "edits[{}]: expected_old 与文件内容不匹配（未命中）。\
                         它必须与原文逐字符一致（含缩进、空行、标点）；建议先用 read_text_lines 读出准确文本再复制过来",
                        idx
                    )),
                }
            }

            if !problems.is_empty() && (all_or_nothing || planned.is_empty()) {
                // 显式指定错误码：混合原因时按“命中不唯一”优先，便于调用方分流
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
            planned.sort_by_key(|(s, _, _, _)| *s);
            for w in planned.windows(2) {
                if w[1].0 < w[0].1 {
                    return Err(e_param(
                        format!(
                            "edits[{}] 与 edits[{}] 的命中范围重叠（参数错误），无法同时应用。请合并为一条，或让两条片段的命中区间互不相交",
                            w[0].3, w[1].3
                        ),
                        None,
                    ));
                }
            }

            // ---- 第三步：按快照一次性拼接 ----
            let mut new_content = String::with_capacity(hay.len());
            let mut cursor = 0usize;
            for (s, e, rep, _) in &planned {
                new_content.push_str(&hay[cursor..*s]);
                new_content.push_str(rep);
                cursor = *e;
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

            if params.dry_run.unwrap_or(false) {
                return Ok(format!(
                    "DRY-RUN | {} | {} | {} 处替换 | {}B→{}B | 未写入文件\n{}预计 sha256:{}\n确认无误后去掉 dry_run 重新调用即可写入",
                    params.path,
                    encoding_label,
                    planned.len(),
                    bytes.len(),
                    new_bytes.len(),
                    Self::unified_diff(&ft.content, &new_content, 200),
                    Self::fingerprint_short_of_bytes(&new_bytes)
                ));
            }

            let bak = Self::backup_before_write(&params.path, "edit_file_sections", Some(&bytes));
            Self::atomic_write_ex(&params.path, &new_bytes, bak.as_ref().map(|b| b.bak.as_path()))
                .map_err(|e| e_internal(format!("E_WRITE 写入失败: {}", e), None))?;
            let mut tail = String::new();
            if let Some(h) = &bak {
                Self::finish_backup(h, &new_bytes);
                tail = " | undoable".to_string();
            }
            let skip_note = if problems.is_empty() {
                String::new()
            } else {
                format!(
                    "\n⚠️ 已跳过 {} 条（all_or_nothing=false）:\n{}",
                    problems.len(),
                    problems.join("\n")
                )
            };
            Ok(format!(
                "OK {} | {} | {} 处替换 | {}B→{}B | sha256:{}{}{}",
                params.path,
                encoding_label,
                planned.len(),
                bytes.len(),
                new_bytes.len(),
                Self::fingerprint_short_of_bytes(&new_bytes),
                tail,
                skip_note
            ))
        })
    }


    /// 正则替换文件文本
    #[tool(
        name = "regex_replace",
        description = "正则替换(支持 $1/$2 捕获组)；只想做纯文本替换就传 literal=true（免转义、$ 按字面量）。max_matches 必填=预期最多替换几处，实际超出即拒绝(防正则过宽误伤)；global 默认 true；dry_run=true 只看 diff",
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

        // literal=true：pattern 按纯文本处理（转义后再编译），replacement 里的 $ 也转成字面量。
        // 这样“把 A 精确换成 B”不需要任何正则知识，也不会被元字符/捕获组引用坑到。
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
        // max_results=0 会让工具“立即截断返回空”，这里兜到至少 1，避免空结果难以归因
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
                .map_err(|e| format!("无法读取目录 {}: {}", dir_path.display(), e))?;
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

        // 文本文件额外回报行数：改完想确认“行数对不对 / 有没有被换行风格弄坏”时，
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
        description = "删除单个文件(不可删目录)。必须显式传 confirm=true 才会真正删除；未确认时返回 E_INVALID_PARAM 并回显文件大小与指纹；删除前自动备份，可用 manage_backups undo 恢复",
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

        // 与该文件的写操作互斥，避免“边写边删”（进程内锁 + 跨进程文件锁）
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
        // timeout=0 会被 reqwest 当成“立即超时”，这里回退到默认 30 秒，避免误传 0 导致请求必然失败
        let timeout_secs = match params.timeout.unwrap_or(30) {
            0 => 30,
            n => n,
        };
        let response_type = params.response_type.as_deref().unwrap_or("text");

        // 进程级共享客户端：复用 TCP/TLS 连接池，避免每次调用重新握手。
        // 超时改为请求级设置，语义与过去"每次新建带超时的客户端"一致。
        static HTTP_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
        let client = HTTP_CLIENT.get_or_init(|| {
            reqwest::Client::builder()
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        });

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

        let mut response = request
            .timeout(std::time::Duration::from_secs(timeout_secs))
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

        // 统一按上限读取响应体：三个分支都不再无限缓冲
        // （旧实现 text/json/binary 都会先把整份响应读进内存，超大响应会 OOM）
        const MAX_FETCH_BODY: usize = 8 * 1024 * 1024;
        let mut body_bytes: Vec<u8> = Vec::new();
        let mut body_truncated = false;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body_bytes.len() + chunk.len() > MAX_FETCH_BODY {
                        let room = MAX_FETCH_BODY - body_bytes.len();
                        body_bytes.extend_from_slice(&chunk[..room]);
                        body_truncated = true;
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return Err(e_internal(format!("读取响应失败: {}", e), None)),
            }
        }
        let body_note = if body_truncated {
            format!("\n... 响应体超过 {}B 上限，已截断", MAX_FETCH_BODY)
        } else {
            String::new()
        };

        match response_type {
            "json" => {
                let body = String::from_utf8_lossy(&body_bytes).into_owned();
                let formatted = serde_json::from_str::<serde_json::Value>(&body)
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| body.clone()))
                    .unwrap_or(body);

                Ok(format!(
                    "{}{}```\n{}\n```{}",
                    status_line, headers_block, formatted, body_note
                ))
            }
            "binary" => {
                let hex_preview: String = body_bytes
                    .iter()
                    .take(256)
                    .map(|b| format!("{:02X} ", b))
                    .collect();
                let truncated = if body_bytes.len() > 256 || body_truncated {
                    format!("\n... {}B total{}", body_bytes.len(), body_note)
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
                let body = String::from_utf8_lossy(&body_bytes).into_owned();

                let preview = if body.len() > 100_000 {
                    // 按字符边界截断：第 10 万字节可能落在多字节字符中间，直接切片会 panic
                    let cut = body.floor_char_boundary(100_000);
                    format!("{}\n... {}B total{}", &body[..cut], body.len(), body_note)
                } else {
                    format!("{}{}", body, body_note)
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
            // 源与目标相同（复制到自身）：直接跳过，否则 overwrite=true 时 fs::copy 会报“文件被占用”
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
            // 跨卷时 rename 会失败（Windows ERROR_NOT_SAME_DEVICE=17 / Unix EXDEV=18），回退为“复制 + 删除”
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
                // 行数不符是“行号算错”最常见的成因，直接点明，省掉一轮试错往返
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
                // 插入点在文件末尾且文件以换行结尾时，split 产生的末尾空串只是“结尾换行标记”，
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
                // 文件以换行结尾时，split 产生的末尾空串只是“结尾换行标记”而不是真实空行：
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