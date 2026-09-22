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
    /// 起始偏移量(字节)，默认0
    offset: Option<u64>,
    /// 读取长度(字节)，默认 10MB 上限。文件更大时会截断并在返回头显著标注，可用 offset 分页读取剩余部分
    length: Option<usize>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
    /// 是否在每行前显示行号，默认false。如需按行编辑配合 edit_file_lines，请使用 read_text_lines 工具
    show_line_numbers: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextLinesParams {
    /// 文件路径
    path: String,
    /// 起始行号(1-based)，默认1
    start_line: Option<usize>,
    /// 结束行号(1-based，包含)，默认到末尾
    end_line: Option<usize>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteTextFileParams {
    /// 文件路径
    path: String,
    /// 写入内容
    content: String,
    /// 写入模式: overwrite(覆盖)/append(追加)/insert(指定位置插入)
    mode: Option<String>,
    /// 插入位置的偏移量(字节)
    offset: Option<u64>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
    /// 期望的旧内容（overwrite 模式写前校验）。若提供且与文件当前内容不一致，则拒绝写入并返回文件完整内容，防止未完整读取就整文件覆盖
    expected_old: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadBinaryFileParams {
    /// 文件路径
    path: String,
    /// 起始偏移量(字节)，默认0
    offset: Option<u64>,
    /// 读取长度(字节)，默认到末尾
    length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteBinaryFileParams {
    /// 文件路径
    path: String,
    /// 十六进制数据，如 "48656C6C6F" 或 "0x48656C6C6F"
    hex_data: String,
    /// 写入模式: overwrite/append/insert/replace
    mode: Option<String>,
    /// 偏移量(字节)。insert为插入位置，replace为替换起始位置
    offset: Option<u64>,
    /// replace模式下被替换的字节数
    replace_length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileInfoParams {
    /// 文件路径
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RegexReplaceParams {
    /// 文件路径
    path: String,
    /// 正则表达式模式
    pattern: String,
    /// 替换内容，支持 $1, $2 捕获组引用
    replacement: String,
    /// 字符串替换时使用的字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
    /// 是否全局替换，默认true。false则仅替换首个匹配
    global: Option<bool>,
    /// 是否仅预览不写入（dry-run）。true 时返回匹配数量、前20处替换预览及新文件大小，不修改文件。默认 false
    dry_run: Option<bool>,
    /// 匹配数量上限，超过则拒绝执行（防止正则过宽或匹配空串导致误替换）。默认 10000
    max_matches: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TextSearchParams {
    /// 文件或目录路径。目录时搜索目录下文件
    path: String,
    /// 搜索模式(正则表达式)
    pattern: String,
    /// 是否区分大小写，默认true
    case_sensitive: Option<bool>,
    /// 最大返回数，默认100
    max_results: Option<usize>,
    /// 文件后缀过滤(如"txt")，仅path为目录时生效
    extension: Option<String>,
    /// 是否递归子目录，默认true。仅path为目录时生效
    recursive: Option<bool>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListFilesParams {
    /// 目录路径
    path: String,
    /// 文件名过滤(正则)，不指定则列出所有。与 glob_pattern 二选一
    pattern: Option<String>,
    /// Glob 通配符过滤(如 "**/*.rs" "*.txt")，比正则更直观。与 pattern 二选一
    glob_pattern: Option<String>,
    /// 是否递归子目录，默认false
    recursive: Option<bool>,
    /// 是否包含目录项，默认true
    include_dirs: Option<bool>,
    /// 最大返回数，默认500
    max_results: Option<usize>,
    /// 是否显示文件大小，默认true
    show_size: Option<bool>,
    /// 是否显示修改时间，默认false
    show_modified: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeleteFileParams {
    /// 文件路径
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FetchParams {
    /// 请求的 URL 地址
    url: String,
    /// HTTP方法，默认GET。可选: GET/POST/PUT/DELETE/PATCH/HEAD
    method: Option<String>,
    /// 请求头键值对
    headers: Option<std::collections::HashMap<String, String>>,
    /// 请求体(字符串)，POST/PUT/PATCH时使用
    body: Option<String>,
    /// 响应类型: text/json/binary，默认text
    response_type: Option<String>,
    /// 超时(秒)，默认30
    timeout: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileLinesParams {
    /// 操作类型: delete_lines(删除行), insert_lines(插入行), replace_lines(替换行), append_lines(追加行)
    operation: String,
    /// 文件路径
    path: Option<String>,
    /// 文件路径(兼容)
    file_path: Option<String>,
    /// 起始行号(1-based)，delete/insert/replace操作使用
    start_line: Option<usize>,
    /// 结束行号(1-based)，delete/replace操作使用
    end_line: Option<usize>,
    /// 要插入/替换/追加的内容
    content: Option<String>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
    /// 期望的旧内容(delete/replace操作必传)。与实际文件的目标行进行比对，不匹配则拒绝操作。用于防止行号算错导致误改。
    expected_old: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CopyFilesParams {
    /// 源文件路径列表
    sources: Vec<String>,
    /// 目标路径。如果是目录则将源文件复制到该目录下；单文件时可指定新文件名
    target: String,
    /// 是否覆盖已存在的目标文件，默认false
    overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MoveFilesParams {
    /// 源文件路径列表
    sources: Vec<String>,
    /// 目标路径。如果是目录则将源文件移动到该目录下；单文件时可指定新文件名
    target: String,
    /// 是否覆盖已存在的目标文件，默认false
    overwrite: Option<bool>,
}

// ==================== MCP 服务器 ====================

#[derive(Clone)]
struct FileIoServer {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    /// 允许访问的根目录（沙箱）。为 None 时不限制路径。
    root: Option<std::path::PathBuf>,
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
                .map_err(|e| McpError::internal_error(format!("无法获取当前目录: {}", e), None))?
                .join(p)
        };

        let root = match &self.root {
            None => return Ok(abs.to_string_lossy().into_owned()),
            Some(r) => r,
        };

        let root_norm = normalize_path(root);
        let abs_norm = normalize_path(&abs);
        if !abs_norm.starts_with(&root_norm) {
            return Err(McpError::invalid_params(
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
                McpError::internal_error(format!("无法解析路径: {}", e), None)
            })?;
            let canon_norm = normalize_path(&canon);
            if !canon_norm.starts_with(&root_norm) {
                return Err(McpError::invalid_params(
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

    /// 自动检测文件编码：BOM → UTF-8 → 常见 CJK 编码
    fn detect_encoding(bytes: &[u8]) -> &'static str {
        // BOM 检测
        if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            return "utf-8";
        }
        if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xFE && bytes[2] == 0x00 && bytes[3] == 0x00 {
            return "utf-32le";
        }
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            return "utf-16le";
        }
        if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
            return "utf-16be";
        }
        if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0xFE && bytes[3] == 0xFF {
            return "utf-32be";
        }

        // 尝试 UTF-8（无 BOM）
        if std::str::from_utf8(bytes).is_ok() {
            return "utf-8";
        }

        // 尝试常见 CJK 编码
        let candidates = ["gbk", "big5", "shift_jis", "euc-jp", "euc-kr"];
        for &enc in &candidates {
            let encoding = encoding_rs::Encoding::for_label(enc.as_bytes()).unwrap();
            let (_, _, had_errors) = encoding.decode(bytes);
            if !had_errors {
                return enc;
            }
        }

        // 兜底用 GBK
        "gbk"
    }

    /// 解析 encoding 参数："auto" 时自动检测，否则返回编码规范名（默认 utf-8）。校验编码有效性
    fn resolve_encoding(param: Option<&str>, bytes: &[u8]) -> Result<&'static str, String> {
        match param {
            Some(name) if name.eq_ignore_ascii_case("auto") => Ok(Self::detect_encoding(bytes)),
            Some(name) => Self::get_encoding(name).map(|e| e.name()),
            None => Ok("utf-8"),
        }
    }

    /// 计算字节的 SHA256 十六进制
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
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
            return Err(McpError::invalid_params(
                format!(
                    "文件不存在: {}。已提供 expected_old 说明期望文件存在，请核对路径",
                    path
                ),
                None,
            ));
        }
        let bytes = fs::read(path)
            .map_err(|e| McpError::internal_error(format!("读取文件失败: {}", e), None))?;

        let actual_content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            Self::decode_bytes(&bytes, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

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
        Err(McpError::invalid_params(
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
                let enc = Self::get_encoding(r).map_err(|e| McpError::invalid_params(e, None))?;
                Ok(enc.name())
            }
            (Some(r), Some(act)) => {
                let enc = Self::get_encoding(r).map_err(|e| McpError::invalid_params(e, None))?;
                let rn = enc.name();
                if rn.eq_ignore_ascii_case(act) {
                    return Ok(rn);
                }
                Err(McpError::invalid_params(
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
        description = "按字节读文本。encoding 默认自动检测并返回实际编码；offset/length 截取，超 10MB 截断时返回头标红。编辑请用 read_text_lines",
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
            .map_err(|e| McpError::internal_error(format!("无法打开文件: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| McpError::internal_error(format!("无法获取文件元数据: {}", e), None))?
            .len();

        let start = params.offset.unwrap_or(0);

        // 若需要显示行号且有偏移，需先读取前面的内容数行数
        let prefix_line_count = if show_ln && start > 0 {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| McpError::internal_error(format!("Seek 失败: {}", e), None))?;
            let mut prefix_buf = vec![0u8; start as usize];
            file.read_exact(&mut prefix_buf)
                .map_err(|e| McpError::internal_error(format!("读取前缀失败: {}", e), None))?;
            // 数前缀中的换行数（即偏移位置处已经过了多少行，行号从1开始，所以行数+1是起始行号）
            prefix_buf.iter().filter(|&&b| b == b'\n').count()
        } else {
            0
        };

        if start >= file_size {
            return Ok(format!("偏移量 {} 超出文件大小 {}", start, file_size));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| McpError::internal_error(format!("Seek 失败: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        let max_len = params.length.unwrap_or(MAX_TEXT_READ_SIZE);
        let read_len = max_len.min(remaining);
        let truncated = read_len < remaining;
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| McpError::internal_error(format!("读取失败: {}", e), None))?;

        let encoding_name = Self::resolve_encoding(params.encoding.as_deref().or(Some("auto")), &buffer)
            .map_err(|e| McpError::invalid_params(e, None))?;
        let content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8(buffer).map_err(|_| {
                McpError::internal_error(
                    format!("文件不是有效的 UTF-8 编码（可能在偏移量 {} 处包含非法字节），请尝试指定正确的 encoding 参数", start),
                    None,
                )
            })?
        } else {
            Self::decode_bytes(&buffer, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
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

        Ok(format!(
            "{}{} | {} | {}B | [{},{}){}```\n{}\n```",
            params.path,
            trunc_warn,
            encoding_name,
            file_size,
            start,
            start + read_len as u64,
            if show_ln { " | lines" } else { "" },
            display_content
        ))
    }

    /// 写入文本文件
    #[tool(
        name = "write_text_file",
        description = "写文本(自动建目录)。mode: overwrite/append/insert。建议传 expected_old 校验：与当前想改范围(overwrite=全文/append=末尾/insert=offset附近)不一致则拒绝并返回实际内容。encoding 默认保持原编码，不一致则拒绝",
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

        // 若文件已存在，读取原字节用于编码检测（写前保持原编码）
        let existing_bytes: Option<Vec<u8>> = if std::path::Path::new(&params.path).exists() {
            Some(fs::read(&params.path).map_err(|e| {
                McpError::internal_error(format!("读取原文件失败: {}", e), None)
            })?)
        } else {
            None
        };

        // 决定写入编码：未指定/auto 时保持原文件编码；指定编码与实际不一致时直接报错返回真实编码
        let encoding_name = Self::resolve_write_encoding(
            &params.path,
            params.encoding.as_deref(),
            existing_bytes.as_deref(),
        )?;

        // 按指定编码将内容转换为字节
        let bytes: Vec<u8> = if encoding_name.eq_ignore_ascii_case("utf-8") {
            params.content.as_bytes().to_vec()
        } else {
            Self::encode_string(&params.content, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| McpError::internal_error(e, None))?;

        // 写前校验（按 mode 校验"当前想改范围"的内容）：防止未确认当前内容就误写
        Self::check_write_guard(
            &params.path,
            encoding_name,
            mode,
            params.offset,
            params.expected_old.as_deref(),
        )?;

        match mode {
            "overwrite" => {
                retry_io(|| fs::write(&params.path, &bytes))
                    .map_err(|e| McpError::internal_error(format!("写入失败: {}", e), None))?;
                Ok(format!("OK {} | {} | {}B", params.path, encoding_name, bytes.len()))
            }
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
                .map_err(|e| McpError::internal_error(format!("追加失败: {}", e), None))?;
                Ok(format!("OK {} | {} | +{}B append", params.path, encoding_name, bytes.len()))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                if !std::path::Path::new(&params.path).exists() {
                    return Err(McpError::invalid_params(
                        format!("insert 模式需要文件已存在，但文件不存在: {}. 请使用 overwrite 模式创建新文件", params.path),
                        None,
                    ));
                }
                let original = fs::read(&params.path).map_err(|e| {
                    McpError::internal_error(format!("读取原文件失败: {}", e), None)
                })?;
                let off = off.min(original.len());
                let mut new_data =
                    Vec::with_capacity(original.len() + bytes.len());
                new_data.extend_from_slice(&original[..off]);
                new_data.extend_from_slice(&bytes);
                new_data.extend_from_slice(&original[off..]);
                retry_io(|| fs::write(&params.path, &new_data)).map_err(|e| {
                    McpError::internal_error(format!("插入写入失败: {}", e), None)
                })?;
                Ok(format!("OK {} | {} | +{}B @{} | {}B", params.path, encoding_name, bytes.len(), off, new_data.len()))
            }
            _ => Ok(format!(
                "不支持的模式: {}，可选: overwrite, append, insert",
                mode
            )),
        }
    }

    /// 按行号读取文本文件（与 edit_file_lines 配合使用，避免行号算错）
    #[tool(
        name = "read_text_lines",
        description = "按行读文本(1-based，带行号)，与 edit_file_lines 配套。encoding 默认自动检测并返回实际编码",
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
                    McpError::internal_error(format!("文件不存在: {}", params.path), None)
                }
                std::io::ErrorKind::PermissionDenied => {
                    McpError::internal_error(format!("没有权限读取文件: {}", params.path), None)
                }
                _ => McpError::internal_error(format!("读取文件失败: {}", e), None),
            }
        })?;

        let file_size = bytes.len();
        let encoding_name = Self::resolve_encoding(params.encoding.as_deref().or(Some("auto")), &bytes)
            .map_err(|e| McpError::invalid_params(e, None))?;

        let file_content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            Self::decode_bytes(&bytes, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 拆分行，保留换行符风格的信息
        let lines: Vec<&str> = file_content.split('\n').collect();
        let total_lines = lines.len();

        let start = params.start_line.unwrap_or(1).max(1);
        let end = params.end_line.unwrap_or(total_lines).min(total_lines);

        if start > end {
            return Err(McpError::invalid_params(
                format!("行号范围无效: start_line({}) > end_line({})，文件总行数: {}", start, end, total_lines),
                None,
            ));
        }
        if start > total_lines {
            return Err(McpError::invalid_params(
                format!("start_line({}) 超出文件总行数({})", start, total_lines),
                None,
            ));
        }

        // 行号显示宽度
        let width = total_lines.to_string().len().max(3);
        let selected: Vec<String> = lines
            .iter()
            .enumerate()
            .skip(start - 1)
            .take(end - start + 1)
            .map(|(i, s)| format!("{:>width$}| {}", i + 1, s.trim_end_matches('\r'), width = width))
            .collect();

        Ok(format!(
            "{} | {} | {}B | {} lines total | [{}-{}]```\n{}\n```",
            params.path,
            encoding_name,
            file_size,
            total_lines,
            start,
            end,
            selected.join("\n")
        ))
    }

    /// 读取二进制文件，返回HEX dump
    #[tool(
        name = "read_binary_file",
        description = "读二进制返回 HEX dump(地址+十六进制+ASCII)。offset/length 截取",
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
            .map_err(|e| McpError::internal_error(format!("无法打开文件: {}", e), None))?;
        let file_size = file
            .metadata()
            .map_err(|e| McpError::internal_error(format!("无法获取文件元数据: {}", e), None))?
            .len();

        let start = params.offset.unwrap_or(0);
        if start >= file_size {
            return Ok(format!("偏移量 {} 超出文件大小 {}", start, file_size));
        }

        file.seek(SeekFrom::Start(start))
            .map_err(|e| McpError::internal_error(format!("Seek 失败: {}", e), None))?;

        let remaining = (file_size - start) as usize;
        let read_len = params.length.unwrap_or(remaining).min(remaining);
        let mut buffer = vec![0u8; read_len];
        file.read_exact(&mut buffer)
            .map_err(|e| McpError::internal_error(format!("读取失败: {}", e), None))?;

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
            "{} | {}B | [{},{})```\n{}```",
            params.path, file_size, start, start + read_len as u64, hex_dump
        ))
    }

    /// 写入十六进制数据到二进制文件
    #[tool(
        name = "write_binary_file",
        description = "写十六进制。mode: overwrite/append/insert(offset)/replace(offset+replace_length)",
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
            return Err(McpError::invalid_params(
                format!("十六进制数据包含非法字符: [{}]。只允许 0-9, A-F, a-f", invalid),
                None,
            ));
        }

        if hex_str.len() % 2 != 0 {
            return Err(McpError::invalid_params(
                "十六进制字符串长度必须为偶数".to_string(),
                None,
            ));
        }

        let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect();
        let bytes = bytes.map_err(|e| {
            McpError::internal_error(format!("十六进制解析失败: {}", e), None)
        })?;

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| McpError::internal_error(e, None))?;

        match mode {
            "overwrite" => {
                retry_io(|| fs::write(&params.path, &bytes))
                    .map_err(|e| McpError::internal_error(format!("写入失败: {}", e), None))?;
                Ok(format!("OK {} | {}B", params.path, bytes.len()))
            }
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
                .map_err(|e| McpError::internal_error(format!("追加失败: {}", e), None))?;
                Ok(format!("OK {} | +{}B append", params.path, bytes.len()))
            }
            "insert" => {
                let off = params.offset.unwrap_or(0) as usize;
                let original = fs::read(&params.path).map_err(|e| {
                    McpError::internal_error(format!("读取原文件失败: {}", e), None)
                })?;
                let off = off.min(original.len());
                let mut new_data =
                    Vec::with_capacity(original.len() + bytes.len());
                new_data.extend_from_slice(&original[..off]);
                new_data.extend_from_slice(&bytes);
                new_data.extend_from_slice(&original[off..]);
                retry_io(|| fs::write(&params.path, &new_data)).map_err(|e| {
                    McpError::internal_error(format!("插入写入失败: {}", e), None)
                })?;
                Ok(format!("OK {} | +{}B @{} | {}B", params.path, bytes.len(), off, new_data.len()))
            }
            "replace" => {
                let off = params.offset.unwrap_or(0) as usize;
                let replace_len = params.replace_length.unwrap_or(0);
                let original = fs::read(&params.path).map_err(|e| {
                    McpError::internal_error(format!("读取原文件失败: {}", e), None)
                })?;

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

                retry_io(|| fs::write(&params.path, &new_data)).map_err(|e| {
                    McpError::internal_error(format!("替换写入失败: {}", e), None)
                })?;

                Ok(format!(
                    "OK {} | {}B→{}B @{} | {}B",
                    params.path,
                    actual_replaced,
                    bytes.len(),
                    off,
                    new_data.len()
                ))
            }
            _ => Ok(format!(
                "不支持的模式: {}，可选: overwrite, append, insert, replace",
                mode
            )),
        }
    }

    /// 搜索文件/目录中的文本内容(正则)
    #[tool(
        name = "text_search",
        description = "正则搜索文件/目录文本。目录时递归，支持 extension 过滤、case_sensitive、max_results",
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
            McpError::invalid_params(format!("正则表达式错误: {}", e), None)
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
                .map_err(|e| McpError::internal_error(e, None))?;
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
        description = "正则替换文件文本，支持 $1/$2 捕获组。global 默认 true；dry_run=true 只预览不写入；匹配数超 max_matches(默认10000) 拒绝防误伤",
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
            .map_err(|e| McpError::internal_error(format!("无法获取文件信息: {}", e), None))?
            .len();
        if file_size > MAX_REGEX_FILE_SIZE {
            return Err(McpError::invalid_params(
                format!(
                    "文件过大 ({}B)，最大支持 {}B。如需处理大文件，请手动分割后操作",
                    file_size, MAX_REGEX_FILE_SIZE
                ),
                None,
            ));
        }

        let bytes = fs::read(&params.path).map_err(|e| {
            McpError::internal_error(format!("读取文件失败: {}", e), None)
        })?;

        let encoding_name = Self::resolve_encoding(params.encoding.as_deref(), &bytes)
            .map_err(|e| McpError::invalid_params(e, None))?;

        // 按指定编码解码
        let content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8(bytes).map_err(|e| {
                McpError::internal_error(
                    format!("文件不是有效的 UTF-8 编码，请尝试指定正确的 encoding 参数: {}", e),
                    None,
                )
            })?
        } else {
            Self::decode_bytes(&bytes, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        let re = Regex::new(&params.pattern).map_err(|e| {
            McpError::invalid_params(format!("正则表达式错误: {}", e), None)
        })?;

        let global = params.global.unwrap_or(true);
        let max_matches = params.max_matches.unwrap_or(10000);

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
            return Err(McpError::invalid_params(
                format!(
                    "匹配数量 {} 超过上限 {}，拒绝执行！请检查正则是否过宽或匹配了空串。确认无误可设置 max_matches 调高上限",
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

        // 按指定编码编码回字节
        let new_bytes = if encoding_name.eq_ignore_ascii_case("utf-8") {
            new_content.as_bytes().to_vec()
        } else {
            Self::encode_string(&new_content, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        retry_io(|| fs::write(&params.path, &new_bytes)).map_err(|e| {
            McpError::internal_error(format!("写入文件失败: {}", e), None)
        })?;

        Ok(format!(
            "{} | {} | {} | {}B→{}B",
            params.path,
            params.pattern,
            count,
            content.len(),
            new_bytes.len()
        ))
    }

    /// 列出或搜索目录内容
    #[tool(
        name = "list_files",
        description = "列目录/搜文件名。pattern(正则)或 glob_pattern 过滤、recursive、show_size/show_modified、include_dirs、max_results",
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
                McpError::invalid_params(format!("正则表达式错误: {}", e), None)
            })?),
            None => None,
        };

        let glob_matcher = match &params.glob_pattern {
            Some(g) => {
                if params.pattern.is_some() {
                    return Err(McpError::invalid_params("pattern 和 glob_pattern 不能同时使用", None));
                }
                let glob = Glob::new(g).map_err(|e| {
                    McpError::invalid_params(format!("Glob 表达式错误: {}", e), None)
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
        .map_err(|e| McpError::internal_error(e, None))?;

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
        description = "获取文件/目录元信息：路径、类型、大小、修改时间(UNIX时间戳)、SHA256哈希",
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
            McpError::internal_error(format!("无法获取文件信息: {}", e), None)
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

        // 计算 SHA256（仅文件，目录输出 "-"）
        let hash = if metadata.is_file() {
            match fs::read(&params.path) {
                Ok(bytes) => Self::sha256_hex(&bytes),
                Err(_) => "-".to_string(),
            }
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
        description = "删除单个文件（不可删除目录）。不可逆，需用户确认授权",
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

        if !path.exists() {
            return Ok(format!("文件不存在: {}", params.path));
        }

        if !path.is_file() {
            return Ok(format!("路径不是普通文件，无法删除: {}", params.path));
        }

        let size = fs::metadata(path)
            .map_err(|e| McpError::internal_error(format!("无法获取文件信息: {}", e), None))?
            .len();

        retry_io(|| fs::remove_file(path)).map_err(|e| {
            McpError::internal_error(format!("删除文件失败: {}", e), None)
        })?;

        Ok(format!("OK {} | {}B deleted", params.path, size))
    }

    /// 发送HTTP请求
    #[tool(
        name = "fetch",
        description = "发送 HTTP 请求。GET/POST/PUT/DELETE/PATCH/HEAD，headers/body/response_type(text|json|binary)/timeout",
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
            .map_err(|e| McpError::internal_error(format!("创建 HTTP 客户端失败: {}", e), None))?;

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
            .map_err(|e| McpError::internal_error(format!("请求失败: {}", e), None))?;

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
                    McpError::internal_error(format!("读取响应失败: {}", e), None)
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
                    McpError::internal_error(format!("读取响应失败: {}", e), None)
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
                    McpError::internal_error(format!("读取响应失败: {}", e), None)
                })?;

                let preview = if body.len() > 100_000 {
                    format!(
                        "{}\n... {}B total",
                        &body[..100_000],
                        body.len()
                    )
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
        description = "批量复制到目录，或单文件改名。自动建目录，overwrite 开关",
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
                return Err(McpError::invalid_params(
                    format!("源文件不存在或不是普通文件: {}", s), None,
                ));
            }
        }

        // 如果是多文件，目标必须是目录
        if sources.len() > 1 && target_path.exists() && !target_is_dir {
            return Err(McpError::invalid_params(
                format!("多文件复制时目标必须是目录: {}", target), None,
            ));
        }

        // 确保目标目录存在
        if target_is_dir {
            retry_io(|| fs::create_dir_all(target_path))
                .map_err(|e| McpError::internal_error(format!("创建目标目录失败: {}", e), None))?;
        } else {
            // 单文件且目标不是目录，确保父目录存在
            if let Some(parent) = target_path.parent() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| McpError::internal_error(format!("创建父目录失败: {}", e), None))?;
            }
        }

        let mut copied = 0u64;
        let mut results = Vec::new();

        for src in &sources {
            let src_path = std::path::Path::new(src);
            let file_name = src_path.file_name().ok_or_else(|| {
                McpError::invalid_params(format!("无法获取文件名: {}", src), None)
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
                .map_err(|e| McpError::internal_error(format!("无法读取源文件信息: {}", e), None))?
                .len();

            retry_io(|| fs::copy(src, &dest))
                .map_err(|e| McpError::internal_error(format!("复制失败 {} -> {}: {}", src, dest.display(), e), None))?;

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
        description = "批量移动到目录，或单文件改名。自动建目录，overwrite 开关",
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
                return Err(McpError::invalid_params(
                    format!("源文件不存在或不是普通文件: {}", s), None,
                ));
            }
        }

        // 如果是多文件，目标必须是目录
        if sources.len() > 1 && target_path.exists() && !target_is_dir {
            return Err(McpError::invalid_params(
                format!("多文件移动时目标必须是目录: {}", target), None,
            ));
        }

        // 确保目标目录存在
        if target_is_dir {
            retry_io(|| fs::create_dir_all(target_path))
                .map_err(|e| McpError::internal_error(format!("创建目标目录失败: {}", e), None))?;
        } else {
            if let Some(parent) = target_path.parent() {
                retry_io(|| fs::create_dir_all(parent))
                    .map_err(|e| McpError::internal_error(format!("创建父目录失败: {}", e), None))?;
            }
        }

        let mut moved = 0u64;
        let mut results = Vec::new();

        for src in &sources {
            let src_path = std::path::Path::new(src);
            let file_name = src_path.file_name().ok_or_else(|| {
                McpError::invalid_params(format!("无法获取文件名: {}", src), None)
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
                .map_err(|e| McpError::internal_error(format!("无法读取源文件信息: {}", e), None))?
                .len();

            retry_io(|| fs::rename(src, &dest))
                .map_err(|e| McpError::internal_error(format!("移动失败 {} -> {}: {}", src, dest.display(), e), None))?;

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
        description = "按行编辑(1-based)：delete/insert/replace/append_lines。delete/replace 必须传 expected_old(读到的原行)校验，不匹配拒绝。自动保持原换行风格与编码",
        annotations(title = "按行编辑文件", destructive_hint = true)
    )]
    fn edit_file_lines(
        &self,
        Parameters(params): Parameters<EditFileLinesParams>,
    ) -> Result<String, McpError> {
        let target = params.path.or(params.file_path).ok_or_else(|| {
            McpError::invalid_params("缺少 path 或 file_path 参数", None)
        })?;
        let target = self.resolve_path(&target)?;

        // 读取文件字节
        let bytes = retry_io(|| fs::read(&target)).map_err(|e| {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    McpError::internal_error(format!("文件不存在: {}", target), None)
                }
                std::io::ErrorKind::PermissionDenied => {
                    McpError::internal_error(format!("没有权限操作文件: {}", target), None)
                }
                _ => McpError::internal_error(format!("读取文件失败: {}", e), None),
            }
        })?;

        // 决定编辑编码：默认保持原文件编码；指定编码与实际不一致时直接报错返回真实编码
        let encoding_name = Self::resolve_write_encoding(&target, params.encoding.as_deref(), Some(&bytes))?;

        // 按编码解码为字符串
        let file_content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            Self::decode_bytes(&bytes, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 检测原文件主换行风格（CRLF/LF），写回时统一恢复，避免局部编辑产生混合换行
        let crlf_count = file_content.matches("\r\n").count();
        let total_lf = file_content.matches('\n').count();
        let line_ending = if crlf_count * 2 > total_lf { "\r\n" } else { "\n" };
        // 拆分为"裸行"（去掉行尾 \r），后续操作在裸行上进行，写回时统一补行尾符
        let lines: Vec<String> = file_content
            .split('\n')
            .map(|s| s.trim_end_matches('\r').to_string())
            .collect();
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
                return Err(McpError::invalid_params(
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

        let result = match params.operation.as_str() {
            "delete_lines" => {
                let start = params.start_line.ok_or_else(|| {
                    McpError::invalid_params("删除行操作需要指定 start_line", None)
                })?;
                let end = params.end_line.ok_or_else(|| {
                    McpError::invalid_params("删除行操作需要指定 end_line", None)
                })?;
                if start < 1 || end > total_lines || start > end {
                    return Err(McpError::invalid_params(
                        format!("行号范围无效: {}-{}，文件总行数: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = params.expected_old.as_deref().ok_or_else(|| {
                    McpError::invalid_params(
                        "delete_lines 必须提供 expected_old（将 read_text_lines 读到的目标行原样传入），用于防止行号算错",
                        None,
                    )
                })?;
                check_expected_old((start - 1)..end, exp)?;
                modified.drain(start - 1..end);
                format!("del {}~{}", start, end)
            }

            "insert_lines" => {
                let start = params.start_line.ok_or_else(|| {
                    McpError::invalid_params("插入行操作需要指定 start_line", None)
                })?;
                let insert_content = params.content.as_ref().ok_or_else(|| {
                    McpError::invalid_params("插入行操作需要指定 content", None)
                })?;
                if start < 1 || start > total_lines + 1 {
                    return Err(McpError::invalid_params(
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
                let start = params.start_line.ok_or_else(|| {
                    McpError::invalid_params("替换行操作需要指定 start_line", None)
                })?;
                let end = params.end_line.ok_or_else(|| {
                    McpError::invalid_params("替换行操作需要指定 end_line", None)
                })?;
                let replace_content = params.content.as_ref().ok_or_else(|| {
                    McpError::invalid_params("替换行操作需要指定 content", None)
                })?;
                if start < 1 || end > total_lines || start > end {
                    return Err(McpError::invalid_params(
                        format!("行号范围无效: {}-{}，文件总行数: {}", start, end, total_lines),
                        None,
                    ));
                }
                let exp = params.expected_old.as_deref().ok_or_else(|| {
                    McpError::invalid_params(
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
                    McpError::invalid_params("追加行操作需要指定 content", None)
                })?;
                let append_lines: Vec<String> = append_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                modified.extend(append_lines);
                format!("append")
            }

            _ => {
                return Err(McpError::invalid_params(
                    format!(
                        "不支持的操作类型: {}，可选: delete_lines, insert_lines, replace_lines, append_lines",
                        params.operation
                    ),
                    None,
                ));
            }
        };

        let new_content = modified.join(line_ending);
        let new_bytes = if encoding_name.eq_ignore_ascii_case("utf-8") {
            new_content.as_bytes().to_vec()
        } else {
            Self::encode_string(&new_content, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 自动创建父目录
        Self::ensure_parent_dir(&target)
            .map_err(|e| McpError::internal_error(e, None))?;

        retry_io(|| fs::write(&target, &new_bytes)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                McpError::internal_error(format!("没有权限操作文件: {}", target), None)
            } else {
                McpError::internal_error(format!("写入文件失败: {}", e), None)
            }
        })?;

        Ok(format!("{} | {} | {}→{}", result, target, total_lines, modified.len()))
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
                "文件 I/O 工具服务器。若启动时设置了 FILE_IO_ROOT 环境变量，则所有文件操作都被限制在该根目录内（沙箱）。\
                 delete_file、write_*、edit_file_lines、regex_replace 会修改或删除文件，属于破坏性操作，请谨慎使用。\
                 fetch 会与外部网络交互。".into(),
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