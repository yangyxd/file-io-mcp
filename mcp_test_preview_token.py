# -*- coding: utf-8 -*-
"""preview_edits -> planToken -> apply_plans 一次性令牌验证"""
import subprocess, json, os, time, sys, re

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\dist\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_token_data"
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

_id = [300]


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
writeb = lambda p, s: open(p, "wb").write(s.encode("utf-8"))
BASE = "a\nb\nc\nd\n"


def tokens_of(t):
    return re.findall(r"planToken:\s*([0-9a-f]{32})", t)


# ---------- T1: preview issues one token per file; files stay untouched ----------
fa, fb = P("t1a.txt"), P("t1b.txt")
call("write_text_file", {"path": fa, "content": BASE})
call("write_text_file", {"path": fb, "content": BASE})
snap = open(fa, "rb").read()
r = call("preview_edits", {"edits": [
    {"path": fa, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    {"path": fb, "operation": "replace_lines", "start_line": 3, "end_line": 3,
     "content": "C", "expected_old": "c"},
]})
t1 = tokens_of(r)
print("T1 preview issues token per file:", ok(len(t1) == 2), "| count:", len(t1))
print("   files untouched:", ok(open(fa, "rb").read() == snap))

# ---------- T2: apply_plans with a single token commits just that file ----------
r = call("apply_plans", {"plan_tokens": [t1[0]]})
print("T2 single-token commit:", ok("1 succeeded, 0 failed" in r and "B" in read(fa)),
      "|", r.replace("\n", " ")[:70])
print("   other file untouched:", ok("C" not in read(fb)))

# ---------- T3: one-time token (reuse rejected) ----------
r = call("apply_plans", {"plan_tokens": [t1[0]]})
print("T3 one-time reuse rejected:", ok("E_INVALID_PARAM" in r), "|", r.replace("\n", " ")[:70])

# ---------- T4: target changed externally -> reject, token cleared ----------
f4 = P("t4.txt")
call("write_text_file", {"path": f4, "content": BASE})
r = call("preview_edits", {"edits": [
    {"path": f4, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"}]})
t4 = tokens_of(r)[0]
writeb(f4, "a\nz\nc\nd\n")  # b -> z by someone else
r = call("apply_plans", {"plan_tokens": [t4]})
print("T4 changed target rejected:", ok("E_EXTERNAL_CHANGED" in r))
print("   token cleared after fail:",
      ok("E_INVALID_PARAM" in call("apply_plans", {"plan_tokens": [t4]})))

# ---------- T5: multi-file batch commit ----------
f5a, f5b = P("t5a.txt"), P("t5b.txt")
call("write_text_file", {"path": f5a, "content": BASE})
call("write_text_file", {"path": f5b, "content": BASE})
r = call("preview_edits", {"edits": [
    {"path": f5a, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    {"path": f5b, "operation": "replace_lines", "start_line": 4, "end_line": 4,
     "content": "D", "expected_old": "d"},
]})
t5 = tokens_of(r)
r = call("apply_plans", {"plan_tokens": t5})
print("T5 batch commit:", ok("2 succeeded, 0 failed" in r), "|", r.replace("\n", " ")[:70])
print("   both applied:", ok("B" in read(f5a) and "D" in read(f5b)))

# ---------- T6: one file changed -> whole batch rejected, all tokens cleared ----------
f6a, f6b = P("t6a.txt"), P("t6b.txt")
call("write_text_file", {"path": f6a, "content": BASE})
call("write_text_file", {"path": f6b, "content": BASE})
r = call("preview_edits", {"edits": [
    {"path": f6a, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    {"path": f6b, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
]})
t6 = tokens_of(r)
writeb(f6a, "a\nz\nc\nd\n")
r = call("apply_plans", {"plan_tokens": t6})
print("T6 batch rejected on change:", ok("E_EXTERNAL_CHANGED" in r and "t6a" in r))
r1 = call("apply_plans", {"plan_tokens": [t6[0]]})
r2 = call("apply_plans", {"plan_tokens": [t6[1]]})
print("   all batch tokens cleared:",
      ok("E_INVALID_PARAM" in r1 and "E_INVALID_PARAM" in r2))
print("   untouched file not written:", ok("B" not in read(f6b)))

# ---------- T7: non-preview edit generates no token (regression) ----------
f7 = P("t7.txt")
call("write_text_file", {"path": f7, "content": BASE})
r = call("edit_file_lines", {"path": f7, "operation": "replace_lines", "start_line": 2,
                            "end_line": 2, "content": "B", "expected_old": "b",
                            "dry_run": True})
print("T7 non-preview no token:", ok("planToken" not in r))

# ---------- T8: concurrency, non-overlapping edits auto-merge ----------
f8 = P("t8.txt")
call("write_text_file", {"path": f8, "content": BASE})
r = call("preview_edits", {"edits": [
    {"path": f8, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"},
    {"path": f8, "operation": "replace_lines", "start_line": 4, "end_line": 4,
     "content": "D", "expected_old": "d"},
]})
t8 = tokens_of(r)
call("apply_plans", {"plan_tokens": [t8[0]]})       # commits line2
r = call("apply_plans", {"plan_tokens": [t8[1]]})   # line4, non-overlapping
c8 = read(f8)
print("T8 non-overlap merge:", ok("1 succeeded" in r and "B" in c8 and "D" in c8),
      "|", c8.replace("\n", " "))

# ---------- T9: invalid token ----------
r = call("apply_plans", {"plan_tokens": ["0" * 32]})
print("T9 invalid token:", ok("E_INVALID_PARAM" in r))

# ---------- T10: context-block preview yields a working token ----------
f10 = P("t10.txt")
call("write_text_file", {"path": f10, "content": BASE})
sha = get_sha(f10)
r = call("preview_edits", {"edits": [
    {"path": f10, "context_before": "a", "context_after": "c", "content": "B",
     "expected_sha256": sha}]})
t10 = tokens_of(r)
r = call("apply_plans", {"plan_tokens": t10})
print("T10 context-block token:",
      ok(len(t10) == 1 and "1 succeeded" in r and "B" in read(f10)))

# ---------- T11: strict requires whole-file sha256 match ----------
f11 = P("t11.txt")
call("write_text_file", {"path": f11, "content": BASE})
r = call("preview_edits", {"edits": [
    {"path": f11, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"}]})
t11 = tokens_of(r)[0]
writeb(f11, "a\nb\nc\nd\ne\n")   # append only: target still locatable
r = call("apply_plans", {"plan_tokens": [t11], "strict": True})
print("T11 strict rejects on sha change:", ok("E_EXTERNAL_CHANGED" in r))

proc.kill()