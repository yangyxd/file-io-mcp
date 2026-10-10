# -*- coding: utf-8 -*-
"""file-io-mcp 新功能验证脚本：通过 MCP stdio 协议调用工具"""
import subprocess, json, os, sys, hashlib, time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\release\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_data"
os.makedirs(TEST_DIR, exist_ok=True)

proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, bufsize=0)
time.sleep(0.5)

def send(msg):
    data = json.dumps(msg, ensure_ascii=False).encode('utf-8') + b'\n'
    proc.stdin.write(data)
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    return json.loads(line)

# 完整握手：initialize -> 响应 -> initialized 通知
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},
    "clientInfo":{"name":"pytest","version":"1.0"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

_id = [100]
def call(name, args):
    _id[0] += 1
    send({"jsonrpc":"2.0","id":_id[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if "result" in r and "content" in r["result"]:
        return "".join(c.get("text","") for c in r["result"]["content"])
    if "error" in r:
        return f"[ERROR] {r['error'].get('message','')}"
    return r

def show(title, s, maxlen=1200):
    print(f"\n===== {title} =====")
    print(s[:maxlen])

P = lambda n: os.path.join(TEST_DIR, n).replace("\\", "/")

# ---------- 1. read_text_file 编码返回 ----------
f1 = P("utf8.txt")
call("write_text_file", {"path": f1, "content": "第一行\n第二行\n"})
show("1.1 read_text_file 默认自动检测编码并返回", call("read_text_file", {"path": f1}))

# ---------- 2. write_text_file overwrite + expected_old ----------
f2 = P("guard.txt")
call("write_text_file", {"path": f2, "content": "alpha\nbeta\ngamma\n"})
show("2.1 overwrite expected_old 匹配 → 允许",
     call("write_text_file", {"path": f2, "content": "alpha\nbeta\nGAMMA\n",
                              "expected_old": "alpha\nbeta\ngamma\n"}))
show("2.2 overwrite expected_old 不匹配 → 拒绝并返回完整内容",
     call("write_text_file", {"path": f2, "content": "!!!", "expected_old": "完全错误的旧内容"}))

# ---------- 3. append/insert 模式 expected_old ----------
f3 = P("mix.txt")
call("write_text_file", {"path": f3, "content": "aaa\nbbb\nccc\n"})
show("3.1 append expected_old 匹配（末尾内容）→ 允许",
     call("write_text_file", {"path": f3, "content": "ddd\n", "mode": "append",
                              "expected_old": "ccc\n"}))
show("3.2 append expected_old 不匹配 → 拒绝并返回末尾内容",
     call("write_text_file", {"path": f3, "content": "xxx\n", "mode": "append",
                              "expected_old": "zzz\n"}))
f3b = P("ins.txt")
call("write_text_file", {"path": f3b, "content": "hello world\n"})
show("3.3 insert expected_old 匹配（offset 处内容）→ 允许",
     call("write_text_file", {"path": f3b, "content": " MY", "mode": "insert", "offset": 5,
                              "expected_old": " world\n"}))
show("3.4 insert expected_old 不匹配 → 拒绝并返回插入点附近内容",
     call("write_text_file", {"path": f3b, "content": " X", "mode": "insert", "offset": 5,
                              "expected_old": " WRONG\n"}))

# ---------- 4. edit_file_lines expected_old 必传 + CRLF ----------
f4 = P("lines.txt")
call("write_text_file", {"path": f4, "content": "line1\nline2\nline3\nline4\n"})
show("4.1 delete_lines 不传 expected_old → 报错必传",
     call("edit_file_lines", {"operation": "delete_lines", "path": f4,
                              "start_line": 2, "end_line": 2}))
show("4.2 replace_lines 传正确 expected_old → 成功",
     call("edit_file_lines", {"operation": "replace_lines", "path": f4,
                              "start_line": 2, "end_line": 2, "content": "TWO",
                              "expected_old": "line2"}))
f5 = P("crlf.txt")
with open(f5.replace("/", "\\"), "wb") as f:
    f.write(b"aaa\r\nbbb\r\nccc\r\n")
call("edit_file_lines", {"operation": "replace_lines", "path": f5,
                         "start_line": 2, "end_line": 2, "content": "BBB",
                         "expected_old": "bbb"})
raw = open(f5.replace("/", "\\"), "rb").read()
show("4.3 CRLF 文件编辑后字节（应仍为 \\r\\n 风格）", repr(raw))
print("  CRLF 保持:", b"aaa\r\nBBB\r\nccc\r\n" == raw)

# ---------- 5. regex_replace dry_run + max_matches ----------
f6 = P("re.txt")
call("write_text_file", {"path": f6, "content": "foo foo foo\nbar\n"})
show("5.1 dry_run 预览不写入", call("regex_replace", {"path": f6, "pattern": "foo", "replacement": "FOO", "dry_run": True, "max_matches": 3}))
show("5.2 dry_run 后文件未变", call("read_text_file", {"path": f6}))
show("5.3 实际写入", call("regex_replace", {"path": f6, "pattern": "foo", "replacement": "FOO", "max_matches": 3}))
show("5.3b 未设置 max_matches 拒绝", call("regex_replace", {"path": f6, "pattern": "bar", "replacement": "BAR"}))
show("5.4 max_matches 超限拒绝", call("regex_replace", {"path": f6, "pattern": "O", "replacement": "0", "max_matches": 2}))

# ---------- 6. 编码一致性 ----------
f7 = P("gbk.txt")
call("write_text_file", {"path": f7, "content": "中文测试", "encoding": "gbk"})
show("6.1 read_text_file 检测出 gbk", call("read_text_file", {"path": f7}))
show("6.2 edit_file_lines 显式指定 utf-8 → 拒绝并返回真实编码",
     call("edit_file_lines", {"operation": "append_lines", "path": f7,
                              "content": "加一行", "encoding": "utf-8"}))
show("6.3 edit_file_lines 不指定编码 → 自动保持 gbk",
     call("edit_file_lines", {"operation": "append_lines", "path": f7, "content": "加一行"}))
show("6.4 追加后仍为 gbk 可读", call("read_text_file", {"path": f7}))
show("6.5 write_text_file 指定 utf-8 覆盖 gbk 文件 → 拒绝",
     call("write_text_file", {"path": f7, "content": "覆盖", "encoding": "utf-8"}))

# ---------- 7. read_text_file 截断标红 ----------
f8 = P("big.txt")
call("write_text_file", {"path": f8, "content": "0123456789" * 500})
show("7.1 length 显式截断 → 返回头标红", call("read_text_file", {"path": f8, "length": 30}))

proc.terminate()
print("\n\n全部验证完成")
