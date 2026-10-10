# -*- coding: utf-8 -*-
"""一致性/边界验证：指纹口径统一、空文件语义、锚点提示"""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_consist_data"
os.makedirs(TEST_DIR, exist_ok=True)
ok = lambda b: "PASS" if b else "**FAIL**"

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
sha_of = lambda s: (s.split("sha256:")[1].split(" ")[0].split("|")[0].strip()
                    if "sha256:" in s else "")

# ---------- C1: 空文件语义 ----------
f = P("empty.pas")
open(f, "wb").write(b"")
r = call("read_text_lines", {"path": f})
print("C1 empty file read:", ok("0 lines total" in r and "0B" in r), "|", r.split("```")[0].strip())
r = call("edit_file_lines", {"path": f, "operation": "append_lines", "content": "first line"})
print("   append to empty file:", ok(open(f, "rb").read() == b"first line"),
      "| bytes:", open(f, "rb").read())

# ---------- C2: 指纹口径一致（小文件：read/file_info/write 三方一致） ----------
f2 = P("fp.pas")
r0 = call("write_text_file", {"path": f2, "content": "a\nb\nc\n"})
r1 = call("read_text_lines", {"path": f2})
r2 = call("read_text_file", {"path": f2})
r3 = call("file_info", {"path": f2})
s0, s1, s2, s3 = sha_of(r0), sha_of(r1), sha_of(r2), sha_of(r3)
print("C2 small-file fingerprints equal:", ok(s0 == s1 == s2 == s3 and len(s1) == 16),
      "|", s0, s1, s2, s3)

# ---------- C3: 大文件（>1MB）四处一致（同一采样算法） ----------
f3 = P("big.pas")
big_content = "x" * 1500000 + "\n" + "中文注释\n" * 200
call("write_text_file", {"path": f3, "content": big_content})
r1 = call("read_text_lines", {"path": f3})
r2 = call("read_text_file", {"path": f3, "length": 1024})
r3 = call("file_info", {"path": f3})
r4 = call("read_binary_file", {"path": f3, "length": 16})
s1, s2, s3, s4 = sha_of(r1), sha_of(r2), sha_of(r3), sha_of(r4)
print("C3 large-file fingerprints equal:", ok(s1 == s2 == s3 == s4 and len(s1) == 16),
      "|", s1, s2, s3, s4)

# ---------- C4: OCC 闭环：用写工具返回的 sha 作为下次写入的 expected_sha256 ----------
f4 = P("occ.pas")
call("write_text_file", {"path": f4, "content": "1\n2\n3\n"})
w = call("edit_file_lines", {"path": f4, "operation": "replace_lines",
                             "start_line": 1, "end_line": 1, "content": "one", "expected_old": "1"})
new_sha = sha_of(w)
r = call("edit_file_lines", {"path": f4, "operation": "replace_lines",
                             "start_line": 2, "end_line": 2, "content": "two", "expected_old": "2",
                             "expected_sha256": new_sha})
print("C4 OCC chain (write-returned sha works as expected_sha256):", ok("ERROR" not in r),
      "|", r.split("|")[0].strip() if "|" in r else r)
# 大文件同样闭环
w = call("edit_file_lines", {"path": f3, "operation": "append_lines", "content": "// tail"})
r = call("write_text_file", {"path": f3, "mode": "append", "content": "// tail2",
                             "expected_sha256": sha_of(w)})
print("   large-file OCC chain:", ok("ERROR" not in r))
if "ERROR" in r:
    print("      write result:", r.replace("\n", " ")[:300])
    print("      prev edit out:", w.replace("\n", " ")[:200], "| extracted sha:", sha_of(w))
    print("      size:", os.path.getsize(f3))

# ---------- C5: 锚点未命中给出相似行提示 ----------
f5 = P("anchor.pas")
call("write_text_file", {"path": f5, "content": "unit A;\nbegin\n  x := 1;\nend.\n"})
r = call("edit_file_lines", {"path": f5, "operation": "replace_lines",
                             "anchor_text": "x := 1;", "content": "  x := 2;", "expected_old": "y"})
print("C5 anchor miss suggests similar lines:",
      ok("E_NOT_FOUND" in r and "likely lines you want to change" in r and "line 3" in r))
print("   ", r.replace("\n", " ")[:150])

proc.kill()
