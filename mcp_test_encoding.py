# -*- coding: utf-8 -*-
"""乱码防护验证：GBK/UTF-16 文件经各写工具后编码是否保持、各类危险操作是否被拦住"""
import subprocess, json, os, time

EXE = r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_enc_data"
os.makedirs(TEST_DIR, exist_ok=True)

proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, bufsize=0)
time.sleep(0.4)


def send(msg):
    proc.stdin.write(json.dumps(msg, ensure_ascii=False).encode('utf-8') + b'\n')
    proc.stdin.flush()


def recv():
    return json.loads(proc.stdout.readline())


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "pytest", "version": "1.0"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

_id = [100]


def call(name, args):
    _id[0] += 1
    send({"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    r = recv()
    if "result" in r and "content" in r["result"]:
        return "".join(c.get("text", "") for c in r["result"]["content"])
    if "error" in r:
        return "[ERROR] " + r["error"].get("message", "")
    return str(r)


P = lambda n: os.path.join(TEST_DIR, n).replace("\\", "/")
ok = lambda b: "PASS" if b else "**FAIL**"


def _try_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def head_field(s, key):
    """从返回头取字段值，如 sha256:xxx"""
    if key not in s:
        return ""
    return s.split(key, 1)[1].split("|")[0].split(" ")[0].strip()


# ---------- T1/T2/T3: GBK 文件 ----------
gbk_text = "unit Test;\r\nbegin\r\n  ShowMessage('中文测试');\r\nend.\r\n"
f_gbk = P("gbk.pas")
open(f_gbk, "wb").write(gbk_text.encode("gbk"))
gbk_cn = "中文测试".encode("gbk")

r = call("read_text_lines", {"path": f_gbk})
enc1 = r.split("|")[1].strip()
print("T1 read gbk -> encoding:", enc1, ok(enc1 == "gbk"))

r = call("regex_replace", {"path": f_gbk, "pattern": "ShowMessage",
                           "replacement": "MsgBox", "max_matches": 1})
raw = open(f_gbk, "rb").read()
gbk_ok = ("gbk" in r or "GBK" in r) and raw.decode("gbk").count("MsgBox") == 1 and gbk_cn in raw
print("T2 regex_replace(no encoding) keeps GBK:", ok(gbk_ok),
      "| cn bytes kept:", gbk_cn in raw, "| utf8-decodable:", _try_utf8(raw))

r = call("edit_file_lines", {"path": f_gbk, "operation": "replace_lines",
                             "start_line": 3, "end_line": 3,
                             "content": "  MsgBox('中文测试');",
                             "expected_old": "  MsgBox('中文测试');"})
raw = open(f_gbk, "rb").read()
print("T3 edit_file_lines keeps GBK:", ok(gbk_cn in raw and _try_utf8(raw) is False))

# ---------- T4: 新建 UTF-16LE 文件应自带 BOM ----------
f_new16 = P("new_utf16.pas")
r = call("write_text_file", {"path": f_new16, "content": "unit A;\r\nend.\r\n",
                             "encoding": "utf-16le"})
raw = open(f_new16, "rb").read()
print("T4 new utf-16le has BOM:", ok(raw[:2] == b"\xff\xfe"), "| head:", raw[:6].hex())
r = call("read_text_lines", {"path": f_new16})
print("   re-read encoding:", r.split("|")[1].strip(), ok("utf-16le(BOM)" in r))

# ---------- T5: 外部产生的无 BOM UTF-16LE 应被识别 ----------
f_nobom = P("nobom_utf16.pas")
open(f_nobom, "wb").write("unit B;\r\nbegin\r\nend.\r\n".encode("utf-16le"))
r = call("read_text_lines", {"path": f_nobom})
print("T5 utf-16le without BOM detected:", r.split("|")[1].strip(), ok("utf-16le" in r))

# ---------- T6/T7: max_matches 必填与上限 ----------
f_re = P("re.pas")
call("write_text_file", {"path": f_re, "content": "aaa\nbbb\naaa\n"})
r = call("regex_replace", {"path": f_re, "pattern": "aaa", "replacement": "zzz"})
print("T6 regex_replace without max_matches rejected:", ok("max_matches" in r and "ERROR" in r))
r = call("regex_replace", {"path": f_re, "pattern": "aaa", "replacement": "zzz", "max_matches": 1})
print("T7 max_matches=1 but 2 matches rejected:", ok("ERROR" in r))
r = call("regex_replace", {"path": f_re, "pattern": "aaa", "replacement": "zzz", "max_matches": 2})
print("   max_matches=2 accepted:", ok("ERROR" not in r and "zzz" in open(f_re).read()))

# ---------- T8: insert 偏移必须落在字符边界 ----------
f_ins = P("ins.pas")
call("write_text_file", {"path": f_ins, "content": "abc中文def"})
raw = open(f_ins, "rb").read()
bad_off = 4  # 落在 "中" 的第二/三字节中间
r = call("write_text_file", {"path": f_ins, "mode": "insert", "offset": bad_off, "content": "X"})
print("T8 insert at mid-char offset rejected:", ok("ERROR" in r and "边界" in r))
r = call("write_text_file", {"path": f_ins, "mode": "insert", "offset": 3, "content": "X"})
print("   insert at char boundary accepted:", ok("ERROR" not in r),
      "| content:", open(f_ins, "rb").read().decode("utf-8", "replace"))

# ---------- T9: 含非法字节的文件拒绝写回 ----------
f_bad = P("bad.pas")
open(f_bad, "wb").write(b"\xef\xbb\xbf" + b"unit C;\r\n" + b"\xff\xfe" + b"bad\r\n")
r = call("read_text_lines", {"path": f_bad})
print("T9 read shows invalid-bytes warning:", ok("U+FFFD" in r or "非法" in r))
r = call("edit_file_lines", {"path": f_bad, "operation": "append_lines", "content": "// x"})
print("   write-back rejected:", ok("ERROR" in r and ("U+FFFD" in r or "非法" in r)))
print("   file unchanged:", ok(open(f_bad, "rb").read().endswith(b"bad\r\n")))

proc.kill()
