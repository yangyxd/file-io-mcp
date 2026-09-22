# -*- coding: utf-8 -*-
"""锚点定位 + dry_run/diff 验证"""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_anchor_data"
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
read = lambda p: open(p, "rb").read().decode("utf-8", "replace")

SRC = "unit T;\r\n// {A}\r\n  ShowMessage('x');\r\n// {A}\r\n  x := 1;\r\nend.\r\n"

# ---------- A1: anchor_text 唯一命中 ----------
f = P("a.pas")
call("write_text_file", {"path": f, "content": SRC.replace("{A}", "only-here")})
r = call("edit_file_lines", {"path": f, "operation": "replace_lines",
                             "anchor_text": "  x := 1;", "content": "  x := 2;",
                             "expected_old": "  x := 1;"})
print("A1 anchor_text unique hit:", ok("ERROR" not in r and "repl 5~5" in r),
      "|", r.split("|")[0].strip() if "|" in r else r)
print("   content changed:", ok("x := 2;" in read(f)))

# ---------- A2: 未命中 ----------
r = call("edit_file_lines", {"path": f, "operation": "replace_lines",
                             "anchor_text": "  not-exist;", "content": "y",
                             "expected_old": "z"})
print("A2 anchor no match:", ok("E_NOT_FOUND" in r))

# ---------- A3: 多处命中 → 拒绝并列出所有行号 ----------
r = call("edit_file_lines", {"path": f, "operation": "replace_lines",
                             "anchor_text": "// only-here", "content": "// changed",
                             "expected_old": "// only-here"})
print("A3 anchor not unique:", ok("E_NOT_UNIQUE" in r and "2, 4" in r.replace("（行: ", "（行:")),
      "|", r.replace("\n", " ")[:110])

# ---------- A4: anchor_occurrence 指定第 2 处 ----------
r = call("edit_file_lines", {"path": f, "operation": "replace_lines",
                             "anchor_text": "// only-here", "anchor_occurrence": 2,
                             "content": "// second", "expected_old": "// only-here"})
print("A4 anchor_occurrence=2:", ok("repl 4~4" in r), "|", read(f).replace("\r\n", " | "))

# ---------- A5: anchor_regex 删除行 ----------
r = call("edit_file_lines", {"path": f, "operation": "delete_lines",
                             "anchor_regex": "^\\s*x := 2;", "expected_old": "  x := 2;"})
print("A5 anchor_regex delete:", ok("ERROR" not in r and "x := 2;" not in read(f)))

# ---------- A6: anchor 与 start_line 互斥 ----------
r = call("edit_file_lines", {"path": f, "operation": "append_lines", "content": "x",
                             "anchor_text": "end.", "start_line": 2})
print("A6 anchor + start_line conflict:", ok("E_INVALID_PARAM" in r))

# ---------- D1: edit_file_lines dry_run ----------
f2 = P("d.pas")
call("write_text_file", {"path": f2, "content": "a\nb\nc\nd\ne\n"})
before = open(f2, "rb").read()
r = call("edit_file_lines", {"path": f2, "operation": "replace_lines",
                             "start_line": 3, "end_line": 3, "content": "C-changed",
                             "expected_old": "c", "dry_run": True})
print("D1 edit dry_run:", ok("DRY-RUN" in r and "未写入文件" in r and "- c" in r and "+ C-changed" in r
                             and "预计 sha256" in r))
print("   file unchanged:", ok(open(f2, "rb").read() == before))

# ---------- D2: write_text_file overwrite dry_run ----------
r = call("write_text_file", {"path": f2, "content": "a\nB\nc\nd\ne\n",
                             "expected_old": "a\nb\nc\nd\ne\n", "dry_run": True})
print("D2 write dry_run:", ok("DRY-RUN" in r and "- b" in r and "+ B" in r
                              and open(f2, "rb").read() == before))

# ---------- D3: write_text_file insert dry_run ----------
r = call("write_text_file", {"path": f2, "mode": "insert", "offset": 2,
                             "content": "INSERTED\n", "dry_run": True})
print("D3 insert dry_run:", ok("DRY-RUN" in r and "mode=insert" in r))
print("   snippet:", " / ".join([l for l in r.split("\n") if l.startswith(("-", "+"))][:4]),
      ok(open(f2, "rb").read() == before))

# ---------- D4: dry_run 后真实写入一致 ----------
r = call("edit_file_lines", {"path": f2, "operation": "replace_lines",
                             "start_line": 3, "end_line": 3, "content": "C-changed",
                             "expected_old": "c"})
print("D4 real write after dry_run:", ok("ERROR" not in r and read(f2).split("\n")[2] == "C-changed"))

# ---------- D5: 大改动 diff 折叠 ----------
f3 = P("big.pas")
call("write_text_file", {"path": f3, "content": "\n".join(f"l{i}" for i in range(600)) + "\n"})
r = call("write_text_file", {"path": f3, "content": "\n".join(f"X{i}" for i in range(600)) + "\n",
                             "dry_run": True})
print("D5 large diff folded:", ok("省略" in r))

proc.kill()
