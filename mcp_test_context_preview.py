# -*- coding: utf-8 -*-
"""上下文块编辑 + 多文件预览 验证（对应 P0 / P1 新增能力）"""
import subprocess, json, os, time, sys, re

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_ctx_data"
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


def get_sha(path):
    r = call("read_text_lines", {"path": path})
    m = re.search(r"sha256:([0-9a-f]+)", r)
    return m.group(1) if m else None


P = lambda n: os.path.join(TEST_DIR, n).replace("\\", "/")
ok = lambda b: "PASS" if b else "**FAIL**"
read = lambda p: open(p, "rb").read().decode("utf-8", "replace")

BASE = "program demo;\r\n  a := 1;\r\n  b := 2;\r\n  c := 3;\r\n  d := 4;\r\n  e := 5;\r\nend.\r\n"

# ---------- C1: 上下文块替换（两帧夹住要改的旧文本）----------
f = P("c1.pas")
call("write_text_file", {"path": f, "content": BASE})
sha = get_sha(f)
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  b := 2;",
                             "context_after": "  d := 4;", "content": "  c := 333;",
                             "expected_sha256": sha})
print("C1 context replace:", ok("ERROR" not in r and "repl 4~4" in r),
      "|", r.split("|")[0].strip() if "|" in r else r)
print("   content changed:", ok("c := 333;" in read(f) and "c := 3;" not in read(f)))

# ---------- C2: 上下文块插入（两帧相邻 → 在其间插入）----------
f = P("c2.pas")
call("write_text_file", {"path": f, "content": BASE})
sha = get_sha(f)
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  a := 1;",
                             "context_after": "  b := 2;", "content": "  INSERTED;",
                             "expected_sha256": sha})
print("C2 context insert:", ok("ERROR" not in r and "ins @3" in r),
      "|", r.split("|")[0].strip() if "|" in r else r)
lines2 = read(f).replace("\r\n", "\n").split("\n")
print("   inserted between a and b:", ok(lines2[2] == "  INSERTED;"))

# ---------- C3: 上下文块落点不唯一 → 拒绝 ----------
f = P("c3.pas")
C3 = "  dup := 1;\r\n  mid := 1;\r\n  other := 9;\r\n  dup := 1;\r\n  mid := 2;\r\n"
call("write_text_file", {"path": f, "content": C3})
sha = get_sha(f)
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  dup := 1;",
                             "context_after": "  mid := 2;", "content": "x",
                             "expected_sha256": sha})
print("C3 context not unique:", ok("E_NOT_UNIQUE" in r and "hit 2 place(s)" in r),
      "|", r.replace("\n", " ")[:130])

# ---------- C4: 上下文块未命中 → 拒绝 ----------
f = P("c4.pas")
call("write_text_file", {"path": f, "content": BASE})
sha = get_sha(f)
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  nope := 1;",
                             "context_after": "  d := 4;", "content": "x",
                             "expected_sha256": sha})
print("C4 context not found:", ok("E_NOT_FOUND" in r))

# ---------- C5: 上下文块缺 expected_sha256 → 拒绝 ----------
f = P("c5.pas")
call("write_text_file", {"path": f, "content": BASE})
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  b := 2;",
                             "context_after": "  d := 4;", "content": "x"})
print("C5 context requires sha256:", ok("E_INVALID_PARAM" in r and "expected_sha256" in r))

# ---------- C6: 上下文块与 expected_old 互斥 ----------
f = P("c6.pas")
call("write_text_file", {"path": f, "content": BASE})
sha = get_sha(f)
r = call("edit_file_lines", {"operation": "replace_lines", "path": f,
                             "context_before": "  b := 2;",
                             "context_after": "  d := 4;", "expected_old": "  c := 3;",
                             "content": "x", "expected_sha256": sha})
print("C6 context vs expected_old conflict:", ok("E_INVALID_PARAM" in r and "mutually exclusive" in r))

# ---------- P1: 多文件预览聚合（只读，文件不变）----------
fa = P("p1a.txt")
fb = P("p1b.txt")
call("write_text_file", {"path": fa, "content": "a\nb\nc\n"})
call("write_text_file", {"path": fb, "content": "x\ny\nz\n"})
before_a = open(fa, "rb").read()
before_b = open(fb, "rb").read()
r = call("preview_edits", {"edits": [
    {"path": fa, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    {"path": fb, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "Y", "expected_old": "y"},
]})
print("P1 preview aggregate:", ok("DRY-RUN" in r and "2 succeeded" in r
                                 and "0 failed" in r),
      "|", r.replace("\n", " ")[:120])
print("   files unchanged:", ok(open(fa, "rb").read() == before_a and open(fb, "rb").read() == before_b))

# ---------- P2: 多文件预览含一个失败项 → 汇总计数 ----------
fa2 = P("p2a.txt")
fb2 = P("p2b.txt")
call("write_text_file", {"path": fa2, "content": "a\nb\nc\n"})
call("write_text_file", {"path": fb2, "content": "x\ny\nz\n"})
r = call("preview_edits", {"edits": [
    {"path": fa2, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    # 这条锚点不存在，应记为失败
    {"path": fb2, "operation": "replace_lines", "anchor_text": "  not-exist;",
     "content": "Y", "expected_old": "nope"},
]})
print("P2 preview with failure:", ok("preview failed" in r and "1 succeeded" in r and "1 failed" in r),
      "|", r.replace("\n", " ")[:140])

proc.kill()
