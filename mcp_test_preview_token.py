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

# ---------- T7: only dry_run mints a token; a real write mints none ----------
f7 = P("t7.txt")
call("write_text_file", {"path": f7, "content": BASE})
r = call("edit_file_lines", {"path": f7, "operation": "replace_lines", "start_line": 2,
                            "end_line": 2, "content": "B", "expected_old": "b"})
print("T7 real write mints no token:",
      ok("planToken" not in r and "B" in read(f7)))

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

# ---------- T12: edit_file_sections dry_run also issues a planToken ----------
f12 = P("t12.txt")
call("write_text_file", {"path": f12, "content": "alpha\nbeta\ngamma\n"})
r = call("edit_file_sections", {"path": f12, "dry_run": True, "edits": [
    {"expected_old": "alpha", "content": "ALPHA"},
    {"expected_old": "gamma", "content": "GAMMA"},
]})
t12 = tokens_of(r)
print("T12 sections dry_run issues token:", ok(len(t12) == 1 and "DRY-RUN" in r),
      "| tokens:", len(t12))
print("   file untouched:", ok(read(f12) == "alpha\nbeta\ngamma\n"))

# ---------- T13: commit that sections plan through apply_plans ----------
r = call("apply_plans", {"plan_tokens": t12})
c12 = read(f12)
print("T13 sections committed via token:",
      ok("1 succeeded, 0 failed" in r and "ALPHA" in c12 and "GAMMA" in c12),
      "|", r.replace("\n", " ")[:70])

# ---------- T14: mixed batch (preview_edits token + sections token) ----------
fa14, fb14 = P("t14a.txt"), P("t14b.txt")
call("write_text_file", {"path": fa14, "content": "a\nb\n"})
call("write_text_file", {"path": fb14, "content": "x\ny\n"})
r = call("preview_edits", {"edits": [
    {"path": fa14, "operation": "replace_lines", "start_line": 2, "end_line": 2,
     "content": "B", "expected_old": "b"}]})
t14a = tokens_of(r)
r = call("edit_file_sections", {"path": fb14, "dry_run": True, "edits": [
    {"expected_old": "y", "content": "Y"}]})
t14b = tokens_of(r)
r = call("apply_plans", {"plan_tokens": t14a + t14b})
print("T14 mixed batch commit:", ok("2 succeeded, 0 failed" in r),
      "|", r.replace("\n", " ")[:78])
print("   both applied:", ok("B" in read(fa14) and "Y" in read(fb14)))

# ---------- T15: edit_file_lines dry_run issues a token ----------
f15 = P("t15.txt")
call("write_text_file", {"path": f15, "content": "l1\nl2\n"})
r = call("edit_file_lines", {"path": f15, "operation": "replace_lines", "start_line": 2,
                            "end_line": 2, "content": "L2", "expected_old": "l2",
                            "dry_run": True})
t15 = tokens_of(r)
print("T15 lines dry_run token:", ok(len(t15) == 1 and "DRY-RUN" in r), "| count:", len(t15))
r = call("apply_plans", {"plan_tokens": t15})
print("   committed via token:", ok("1 succeeded" in r and "L2" in read(f15)))

# ---------- T16: regex_replace dry_run issues a token ----------
f16 = P("t16.txt")
call("write_text_file", {"path": f16, "content": "foo\nfoo\n"})
r = call("regex_replace", {"path": f16, "pattern": "foo", "replacement": "bar",
                           "literal": True, "max_matches": 2, "dry_run": True})
t16 = tokens_of(r)
print("T16 regex dry_run token:", ok(len(t16) == 1), "| count:", len(t16))
r = call("apply_plans", {"plan_tokens": t16})
print("   committed via token:",
      ok("1 succeeded" in r and "bar" in read(f16) and "foo" not in read(f16)))

# ---------- T17: write_text_file dry_run issues a token (no content resend) ----------
f17 = P("t17.txt")
call("write_text_file", {"path": f17, "content": "old\n"})
sha17 = call("read_text_lines", {"path": f17}).split("sha256:")[1].split(" ")[0]
r = call("write_text_file", {"path": f17, "content": "new\nnew2\n",
                             "expected_sha256": sha17, "dry_run": True})
t17 = tokens_of(r)
print("T17 write_text dry_run token:", ok(len(t17) == 1), "| count:", len(t17))
print("   file untouched:", ok(read(f17) == "old\n"))
r = call("apply_plans", {"plan_tokens": t17})
print("   committed via token:", ok("1 succeeded" in r and read(f17) == "new\nnew2\n"))

# ---------- T18: write_binary_file dry_run issues a token ----------
f18 = P("t18.bin")
r = call("write_binary_file", {"path": f18, "hex_data": "48656C6C6F",
                               "mode": "overwrite", "confirm": True, "dry_run": True})
t18 = tokens_of(r)
print("T18 write_binary dry_run token:", ok(len(t18) == 1), "| count:", len(t18))
r = call("apply_plans", {"plan_tokens": t18})
print("   committed via token:", ok("1 succeeded" in r and "Hello" in read(f18)))

# ---------- T19: tokens from different tools can be committed in one batch ----------
fa19, fb19, fc19 = P("t19a.txt"), P("t19b.txt"), P("t19c.txt")
for p19 in (fa19, fb19, fc19):
    call("write_text_file", {"path": p19, "content": "x\n"})
r = call("preview_edits", {"edits": [
    {"path": fa19, "operation": "replace_lines", "start_line": 1, "end_line": 1,
     "content": "A", "expected_old": "x"}]})
tk_a = tokens_of(r)
r = call("edit_file_lines", {"path": fb19, "operation": "replace_lines", "start_line": 1,
                             "end_line": 1, "content": "B", "expected_old": "x",
                             "dry_run": True})
tk_b = tokens_of(r)
r = call("regex_replace", {"path": fc19, "pattern": "x", "replacement": "C",
                           "literal": True, "max_matches": 1, "dry_run": True})
tk_c = tokens_of(r)
r = call("apply_plans", {"plan_tokens": tk_a + tk_b + tk_c})
print("T19 cross-tool batch:", ok("3 succeeded, 0 failed" in r),
      "|", r.replace("\n", " ")[:78])
print("   all applied:",
      ok(read(fa19) == "A\n" and read(fb19) == "B\n" and read(fc19) == "C\n"))

proc.kill()