use rmcp::{
    handler::server::wrapper::Parameters,
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_router, tool_handler,
    ErrorData as McpError, ServerHandler, ServiceExt, transport::stdio,
};
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use regex::Regex;

// ==================== 参数结构体 ====================

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadTextFileParams {
    /// 文件路径
    path: String,
    /// 起始偏移量(字节)，默认0
    offset: Option<u64>,
    /// 读取长度(字节)，默认到末尾
    length: Option<usize>,
    /// 字符编码，默认utf-8。支持: gbk, gb2312, gb18030, big5, shift_jis, euc-jp, euc-kr等
    encoding: Option<String>,
    /// 输出格式: markdown(默认，元信息+代码块)/json(纯文本格式)
    output_format: Option<String>,
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
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadBinaryFileParams {
    /// 文件路径
    path: String,
    /// 起始偏移量(字节)，默认0
    offset: Option<u64>,
    /// 读取长度(字节)，默认到末尾
    length: Option<usize>,
    /// 输出格式: markdown(默认，元信息+代码块)/json(纯文本格式)
    output_format: Option<String>,
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
struct GetFileInfoParams {
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
    /// 是否全局替换，默认true。false则仅替换首个匹配
    global: Option<bool>,
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
    /// 输出格式: markdown(默认，元信息+代码块)/json(纯文本格式)
    output_format: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListFilesParams {
    /// 目录路径
    path: String,
    /// 文件名过滤(正则)，不指定则列出所有
    pattern: Option<String>,
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
    /// 输出格式: markdown(默认，表格)/json(纯文本格式)
    output_format: Option<String>,
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
    /// 输出格式: text(默认)/json
    output_format: Option<String>,
}

// ==================== MCP 服务器 ====================

#[derive(Clone)]
struct FileIoServer {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

impl FileIoServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// 确保文件所在目录存在，不存在则自动创建
    fn ensure_parent_dir(path: &str) -> Result<(), String> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
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
        description = "读取文本文件。支持offset(字节偏移)和length(字节长度)截取，encoding指定编码(默认utf-8)"
    )]
    fn read_text_file(
        &self,
        Parameters(params): Parameters<ReadTextFileParams>,
    ) -> Result<String, McpError> {
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

        let encoding_name = params.encoding.as_deref().unwrap_or("utf-8");
        let content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(&buffer).into_owned()
        } else {
            Self::decode_bytes(&buffer, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        let output_format = params.output_format.as_deref().unwrap_or("markdown");
        match output_format {
            "json" => Ok(format!(
                "文件: {}\n编码: {}\n大小: {} 字节\n读取范围: {} - {}\n内容:\n{}",
                params.path, encoding_name, file_size, start, start + read_len as u64, content
            )),
            _ => Ok(format!(
                "文件: {}\n编码: {}\n大小: {} 字节\n读取范围: {} - {}\n\n```\n{}\n```",
                params.path, encoding_name, file_size, start, start + read_len as u64, content
            )),
        }
    }

    /// 写入文本文件
    #[tool(
        name = "write_text_file",
        description = "写入文本文件。目录不存在自动创建。mode: overwrite(默认)/append/insert，支持encoding指定编码"
    )]
    fn write_text_file(
        &self,
        Parameters(params): Parameters<WriteTextFileParams>,
    ) -> Result<String, McpError> {
        let mode = params.mode.as_deref().unwrap_or("overwrite");
        let encoding_name = params.encoding.as_deref().unwrap_or("utf-8");

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

        match mode {
            "overwrite" => {
                fs::write(&params.path, &bytes)
                    .map_err(|e| McpError::internal_error(format!("写入失败: {}", e), None))?;
                Ok(format!(
                    "已覆盖写入 {} (编码: {}, {} 字节)",
                    params.path, encoding_name, bytes.len()
                ))
            }
            "append" => {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&params.path)
                    .map_err(|e| {
                        McpError::internal_error(format!("打开文件失败: {}", e), None)
                    })?;
                file.write_all(&bytes)
                    .map_err(|e| McpError::internal_error(format!("追加失败: {}", e), None))?;
                Ok(format!(
                    "已追加到 {} (编码: {}, {} 字节)",
                    params.path, encoding_name, bytes.len()
                ))
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
                fs::write(&params.path, &new_data).map_err(|e| {
                    McpError::internal_error(format!("插入写入失败: {}", e), None)
                })?;
                Ok(format!(
                    "已在偏移量 {} 处插入 {} 字节 (编码: {})，文件新大小: {} 字节",
                    off, bytes.len(), encoding_name, new_data.len()
                ))
            }
            _ => Ok(format!(
                "不支持的模式: {}，可选: overwrite, append, insert",
                mode
            )),
        }
    }

    /// 读取二进制文件，返回HEX dump
    #[tool(
        name = "read_binary_file",
        description = "读取二进制文件，返回HEX dump。支持offset和length截取"
    )]
    fn read_binary_file(
        &self,
        Parameters(params): Parameters<ReadBinaryFileParams>,
    ) -> Result<String, McpError> {
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

        let output_format = params.output_format.as_deref().unwrap_or("markdown");
        match output_format {
            "json" => Ok(format!(
                "文件: {}\n大小: {} 字节\n读取范围: {} - {} ({} 字节)\nHEX DUMP:\n{}",
                params.path, file_size, start, start + read_len as u64, read_len, hex_dump
            )),
            _ => Ok(format!(
                "文件: {}\n大小: {} 字节\n读取范围: {} - {} ({} 字节)\n\n```\n{}```",
                params.path, file_size, start, start + read_len as u64, read_len, hex_dump
            )),
        }
    }

    /// 写入十六进制数据到二进制文件
    #[tool(
        name = "write_binary_file",
        description = "写入十六进制数据到二进制文件。目录不存在自动创建。mode: overwrite/append/insert/replace"
    )]
    fn write_binary_file(
        &self,
        Parameters(params): Parameters<WriteBinaryFileParams>,
    ) -> Result<String, McpError> {
        let mode = params.mode.as_deref().unwrap_or("overwrite");
        // 兼容处理：去掉 0x 前缀
        let hex_str = params.hex_data.trim();
        let hex_str = if hex_str.starts_with("0x") {
            &hex_str[2..]
        } else {
            hex_str
        };
        let clean_hex: String = hex_str
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();

        if clean_hex.len() % 2 != 0 {
            return Ok("错误: 十六进制字符串长度必须为偶数".to_string());
        }

        let bytes: Result<Vec<u8>, _> = (0..clean_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_hex[i..i + 2], 16))
            .collect();
        let bytes = bytes.map_err(|e| {
            McpError::internal_error(format!("十六进制解析失败: {}", e), None)
        })?;

        // 自动创建父目录
        Self::ensure_parent_dir(&params.path)
            .map_err(|e| McpError::internal_error(e, None))?;

        match mode {
            "overwrite" => {
                fs::write(&params.path, &bytes)
                    .map_err(|e| McpError::internal_error(format!("写入失败: {}", e), None))?;
                Ok(format!(
                    "已覆盖写入 {} ({} 字节)",
                    params.path,
                    bytes.len()
                ))
            }
            "append" => {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&params.path)
                    .map_err(|e| {
                        McpError::internal_error(format!("打开文件失败: {}", e), None)
                    })?;
                file.write_all(&bytes)
                    .map_err(|e| McpError::internal_error(format!("追加失败: {}", e), None))?;
                Ok(format!(
                    "已追加到 {} ({} 字节)",
                    params.path,
                    bytes.len()
                ))
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
                fs::write(&params.path, &new_data).map_err(|e| {
                    McpError::internal_error(format!("插入写入失败: {}", e), None)
                })?;
                Ok(format!(
                    "已在偏移量 {} 处插入 {} 字节，文件新大小: {} 字节",
                    off,
                    bytes.len(),
                    new_data.len()
                ))
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

                fs::write(&params.path, &new_data).map_err(|e| {
                    McpError::internal_error(format!("替换写入失败: {}", e), None)
                })?;

                Ok(format!(
                    "已在偏移量 {} 处替换 {} 字节为 {} 字节，文件新大小: {} 字节 (原大小: {} 字节)",
                    off,
                    actual_replaced,
                    bytes.len(),
                    new_data.len(),
                    original.len()
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
        description = "搜索文件或目录中的文本内容(正则)。path为目录时递归搜索，支持extension后缀过滤"
    )]
    fn text_search(
        &self,
        Parameters(params): Parameters<TextSearchParams>,
    ) -> Result<String, McpError> {
        let case_sensitive = params.case_sensitive.unwrap_or(true);
        let max_results = params.max_results.unwrap_or(100);
        let recursive = params.recursive.unwrap_or(true);

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

        // 收集需要搜索的文件列表
        let files: Vec<String> = if is_dir {
            let mut files = Vec::new();
            Self::collect_files(path, &ext_filter, recursive, max_results, &mut files)
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

            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue, // 跳过无法读取的文件（如二进制文件）
            };

            searched_files += 1;
            let mut file_has_match = false;

            for (line_idx, line) in content.lines().enumerate() {
                for mat in re.find_iter(line) {
                    if results.len() >= max_results {
                        break;
                    }
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
                if results.len() >= max_results {
                    break;
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

        let scope = if is_dir {
            format!("目录: {} (递归: {})", params.path, if recursive { "是" } else { "否" })
        } else {
            format!("文件: {}", params.path)
        };

        let ext_info = ext_filter.as_ref()
            .map(|e| format!("\n后缀过滤: .{}", e))
            .unwrap_or_default();

        let output_format = params.output_format.as_deref().unwrap_or("markdown");
        match output_format {
            "json" => Ok(format!(
                "{}{}\n模式: {} (大小写: {})\n搜索文件: {} 个  匹配文件: {} 个  匹配数: {}\n结果:\n{}{}",
                scope,
                ext_info,
                params.pattern,
                if case_sensitive { "敏感" } else { "不敏感" },
                searched_files,
                matched_files,
                total_matches,
                results.join("\n"),
                truncated
            )),
            _ => Ok(format!(
                "{}{}\n模式: {} (大小写: {})\n搜索文件: {} 个  匹配文件: {} 个  匹配数: {}\n\n```\n{}{}```",
                scope,
                ext_info,
                params.pattern,
                if case_sensitive { "敏感" } else { "不敏感" },
                searched_files,
                matched_files,
                total_matches,
                results.join("\n"),
                truncated
            )),
        }
    }

    /// 正则替换文件文本
    #[tool(
        name = "regex_replace",
        description = "正则替换文件文本。支持$1/$2捕获组引用。global默认true全局替换"
    )]
    fn regex_replace(
        &self,
        Parameters(params): Parameters<RegexReplaceParams>,
    ) -> Result<String, McpError> {
        let content = fs::read_to_string(&params.path).map_err(|e| {
            McpError::internal_error(format!("读取文件失败: {}", e), None)
        })?;

        let re = Regex::new(&params.pattern).map_err(|e| {
            McpError::invalid_params(format!("正则表达式错误: {}", e), None)
        })?;

        let global = params.global.unwrap_or(true);
        let (new_content, count) = if global {
            let count = re.find_iter(&content).count();
            let result = re.replace_all(&content, params.replacement.as_str());
            (result.into_owned(), count)
        } else {
            let count = if re.is_match(&content) { 1 } else { 0 };
            let result = re.replacen(&content, 1, params.replacement.as_str());
            (result.into_owned(), count)
        };

        if count == 0 {
            return Ok(format!(
                "文件: {}\n模式: {}\n未找到匹配项，文件未修改",
                params.path, params.pattern
            ));
        }

        fs::write(&params.path, &new_content).map_err(|e| {
            McpError::internal_error(format!("写入文件失败: {}", e), None)
        })?;

        Ok(format!(
            "文件: {}\n模式: {}\n替换: {} 处\n文件大小: {} -> {} 字节",
            params.path,
            params.pattern,
            count,
            content.len(),
            new_content.len()
        ))
    }

    /// 列出或搜索目录内容
    #[tool(
        name = "list_files",
        description = "列出目录内容或按文件名正则搜索文件。支持递归子目录、过滤、显示大小和修改时间"
    )]
    fn list_files(
        &self,
        Parameters(params): Parameters<ListFilesParams>,
    ) -> Result<String, McpError> {
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
                        &entry.path(), re, recursive, include_dirs, max_results,
                        show_size, show_modified, entries, file_count, dir_count,
                        scanned_dirs, total_size,
                    )?;
                    if entries.len() >= max_results { return Ok(()); }
                }

                // 决定是否匹配当前条目
                let matched = match &re {
                    Some(re) => re.is_match(&name),
                    None => true,
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

        let size_info = if show_size {
            format!("  总大小: {} 字节", total_size)
        } else {
            String::new()
        };

        let output_format = params.output_format.as_deref().unwrap_or("markdown");
        match output_format {
            "json" => {
                let lines: Vec<String> = entries.iter().map(|(path, is_dir, size, modified)| {
                    let type_str = if *is_dir { "[目录]" } else { "[文件]" };
                    let mut info = format!("  {} {}", path, type_str);
                    if show_size && !is_dir {
                        info.push_str(&format!("  ({} 字节)", size));
                    }
                    if show_modified && !modified.is_empty() {
                        info.push_str(&format!("  [修改: {}]", modified));
                    }
                    info
                }).collect();
                Ok(format!(
                    "目录: {}\n文件: {} 个  目录: {} 个  扫描目录: {} 个{}\n结果:\n{}{}",
                    params.path, file_count, dir_count, scanned_dirs, size_info,
                    lines.join("\n"), truncated
                ))
            }
            _ => {
                // markdown 表格输出
                let has_modified = show_modified && entries.iter().any(|(_, _, _, m)| !m.is_empty());
                let mut table = String::from("| 名称 | 类型 |");
                if show_size { table.push_str(" 大小 |"); }
                if has_modified { table.push_str(" 修改时间 |"); }
                table.push('\n');
                table.push_str("|------|------|");
                if show_size { table.push_str("------|"); }
                if has_modified { table.push_str("----------|"); }
                table.push('\n');

                for (path, is_dir, size, modified) in &entries {
                    let type_str = if *is_dir { "目录" } else { "文件" };
                    table.push_str(&format!("| {} | {} |", path, type_str));
                    if show_size {
                        if *is_dir {
                            table.push_str(" - |");
                        } else {
                            table.push_str(&format!(" {} 字节 |", size));
                        }
                    }
                    if has_modified {
                        if modified.is_empty() {
                            table.push_str(" - |");
                        } else {
                            table.push_str(&format!(" {} |", modified));
                        }
                    }
                    table.push('\n');
                }

                Ok(format!(
                    "目录: {}\n文件: {} 个  目录: {} 个  扫描目录: {} 个{}\n\n{}{}",
                    params.path, file_count, dir_count, scanned_dirs, size_info,
                    table, truncated
                ))
            }
        }
    }

    /// 获取文件元信息
    #[tool(
        name = "get_file_info",
        description = "获取文件/目录元信息(大小、类型、修改时间)"
    )]
    fn get_file_info(
        &self,
        Parameters(params): Parameters<GetFileInfoParams>,
    ) -> Result<String, McpError> {
        let metadata = fs::metadata(&params.path).map_err(|e| {
            McpError::internal_error(format!("无法获取文件信息: {}", e), None)
        })?;

        let modified_str = metadata
            .modified()
            .ok()
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| format!("{} 秒 (UNIX时间戳)", d.as_secs()))
                    .unwrap_or_else(|_| "未知".to_string())
            })
            .unwrap_or_else(|| "未知".to_string());

        let file_type = if metadata.is_file() {
            "文件"
        } else if metadata.is_dir() {
            "目录"
        } else {
            "其他"
        };

        Ok(format!(
            "路径: {}\n类型: {}\n大小: {} 字节\n修改时间: {}",
            params.path,
            file_type,
            metadata.len(),
            modified_str
        ))
    }

    /// 删除文件(需用户确认)
    #[tool(
        name = "delete_file",
        description = "删除文件(不可目录)。不可逆，需用户确认"
    )]
    fn delete_file(
        &self,
        Parameters(params): Parameters<DeleteFileParams>,
    ) -> Result<String, McpError> {
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

        fs::remove_file(path).map_err(|e| {
            McpError::internal_error(format!("删除文件失败: {}", e), None)
        })?;

        Ok(format!(
            "已删除文件: {} (原大小: {} 字节)",
            params.path, size
        ))
    }

    /// 发送HTTP请求
    #[tool(
        name = "fetch",
        description = "发送HTTP请求。支持GET/POST/PUT/DELETE/PATCH/HEAD、自定义headers、body、响应格式(text/json/binary)"
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
                resp_headers.push(format!("  {}: {}", key, v));
            }
        }
        let status_line = format!("状态: {} {}", status, status_text);
        let headers_block = if resp_headers.is_empty() {
            String::new()
        } else {
            format!("\n响应头:\n{}", resp_headers.join("\n"))
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
                    "{}{}\n\n```\n{}\n```",
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
                    format!("\n... 已截断，仅显示前 256 字节（共 {} 字节）", bytes.len())
                } else {
                    String::new()
                };

                Ok(format!(
                    "{}{}\n大小: {} 字节\n\n```\n{}{}```",
                    status_line, headers_block, bytes.len(), hex_preview, truncated
                ))
            }
            _ => {
                // text
                let body = response.text().await.map_err(|e| {
                    McpError::internal_error(format!("读取响应失败: {}", e), None)
                })?;

                let preview = if body.len() > 100_000 {
                    format!(
                        "{}\n... 已截断，仅显示前 100KB（共 {} 字节）",
                        &body[..100_000],
                        body.len()
                    )
                } else {
                    body
                };

                Ok(format!(
                    "{}{}\n\n```\n{}\n```",
                    status_line, headers_block, preview
                ))
            }
        }
    }

    /// 按行编辑文件：删除/插入/替换/追加行
    #[tool(
        name = "edit_file_lines",
        description = "按行编辑文件内容。支持 delete_lines(删除行)、insert_lines(插入行)、replace_lines(替换行)、append_lines(追加行)。行号从1开始计数。支持多种编码"
    )]
    fn edit_file_lines(
        &self,
        Parameters(params): Parameters<EditFileLinesParams>,
    ) -> Result<String, McpError> {
        let target = params.path.or(params.file_path).ok_or_else(|| {
            McpError::invalid_params("缺少 path 或 file_path 参数", None)
        })?;

        let encoding_name = params.encoding.as_deref().unwrap_or("utf-8");

        // 读取文件字节
        let bytes = fs::read(&target).map_err(|e| {
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

        // 按编码解码为字符串
        let file_content = if encoding_name.eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            Self::decode_bytes(&bytes, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 拆分行（保留尾部 \r 以兼容 \r\n 换行符）
        let lines: Vec<&str> = file_content.split('\n').collect();
        let total_lines = lines.len();
        let mut modified: Vec<String> = lines.iter().map(|&s| s.to_string()).collect();

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
                modified.drain(start - 1..end);
                format!("成功删除第 {} 到第 {} 行", start, end)
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
                format!("成功在第 {} 行插入内容", start)
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
                let replace_lines: Vec<String> = replace_content
                    .split('\n')
                    .map(|s| s.trim_end_matches('\r').to_string())
                    .collect();
                modified.splice(start - 1..end, replace_lines);
                format!("成功替换第 {} 到第 {} 行", start, end)
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
                format!("成功在文件末尾追加内容")
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

        let new_content = modified.join("\n");
        let new_bytes = if encoding_name.eq_ignore_ascii_case("utf-8") {
            new_content.as_bytes().to_vec()
        } else {
            Self::encode_string(&new_content, encoding_name)
                .map_err(|e| McpError::internal_error(e, None))?
        };

        // 自动创建父目录
        Self::ensure_parent_dir(&target)
            .map_err(|e| McpError::internal_error(e, None))?;

        fs::write(&target, &new_bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                McpError::internal_error(format!("没有权限操作文件: {}", target), None)
            } else {
                McpError::internal_error(format!("写入文件失败: {}", e), None)
            }
        })?;

        let fmt = params.output_format.as_deref().unwrap_or("text");
        if fmt == "json" {
            let json = serde_json::json!({
                "action": params.operation,
                "path": target,
                "total_lines_before": total_lines,
                "total_lines_after": modified.len()
            });
            Ok(serde_json::to_string_pretty(&json).unwrap_or_default())
        } else {
            Ok(format!(
                "{}\n文件: {}\n总行数: {} → {}",
                result, target, total_lines, modified.len()
            ))
        }
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
            instructions: None,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = FileIoServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}