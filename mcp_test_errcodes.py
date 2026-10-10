# -*- coding: utf-8 -*-
"""错误码规范验证：各类失败场景是否返回预期 E_XXX 码"""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_err_data"
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


def expect(label, out, code, must_error=True):
    got_err = out.startswith("[ERROR]")
    has_code = code in out
    passed = has_code and (got_err == must_error)
    print(f"{label:<46} {code:<22} {'PASS' if passed else '**FAIL**'}")
    if not passed:
        print("      ->", out[:220].replace("\n", " | "))
    return passed


f = P("e.pas")
call("write_text_file", {"path": f, "content": "line1\nline2\nline3\n"})

# 1) 不存在的文件
expect("read missing file", call("read_text_lines", {"path": P("nope.pas")}), "E_NOT_FOUND")
# 2) 参数错误：不支持的操作
expect("bad operation", call("edit_file_lines", {"path": f, "operation": "bogus"}), "E_INVALID_PARAM")
# 3) 缺少必填参数
expect("missing required arg", call("regex_replace", {"path": f, "pattern": "x", "replacement": "y"}),
       "E_INVALID_PARAM")
# 4) expected_old 不匹配
expect("expected_old mismatch", call("edit_file_lines", {
    "path": f, "operation": "replace_lines", "start_line": 1, "end_line": 1,
    "content": "X", "expected_old": "totally-wrong"}), "E_GUARD_MISMATCH")
# 5) 行号越界
expect("line out of range", call("edit_file_lines", {
    "path": f, "operation": "delete_lines", "start_line": 99, "end_line": 100,
    "expected_old": "x"}), "E_INVALID_PARAM")
# 6) 编码不一致
call("write_text_file", {"path": P("u16.pas"), "content": "a\r\nb\r\n", "encoding": "utf-16le"})
expect("encoding mismatch", call("edit_file_lines", {
    "path": P("u16.pas"), "operation": "append_lines", "content": "c", "encoding": "utf-8"}),
       "E_ENCODING")
# 7) max_matches 超限
call("write_text_file", {"path": P("re.pas"), "content": "aaa\naaa\n"})
expect("max_matches exceeded", call("regex_replace", {
    "path": P("re.pas"), "pattern": "aaa", "replacement": "z", "max_matches": 1}),
       "E_TOO_MANY_MATCHES")
# 8) 正则语法错误
expect("bad regex", call("regex_replace", {
    "path": P("re.pas"), "pattern": "([", "replacement": "z", "max_matches": 3}),
       "E_INVALID_PARAM")
# 9) 并发版本冲突
r = call("read_text_lines", {"path": f})
sha = r.split("sha256:")[1].split(" ")[0]
call("edit_file_lines", {"path": f, "operation": "replace_lines", "start_line": 2, "end_line": 2,
                         "content": "line2-changed", "expected_old": "line2"})
expect("stale sha", call("edit_file_lines", {
    "path": f, "operation": "replace_lines", "start_line": 3, "end_line": 3,
    "content": "line3-changed", "expected_old": "line3", "expected_sha256": sha}),
       "E_EXTERNAL_CHANGED")
# 10) 路径越界（沙箱） -- 未设置 FILE_IO_ROOT 时会正常返回，跳过
# 11) 备份：无可回滚内容
expect("undo without backup", call("manage_backups", {"path": P("nope2.pas"), "action": "undo"}),
       "E_NOT_FOUND")
# 12) 备份：不支持的 action
expect("bad backup action", call("manage_backups", {"path": f, "action": "bogus"}),
       "E_INVALID_PARAM")
# 13) 十六进制非法
expect("bad hex", call("write_binary_file", {"path": P("b.bin"), "hex_data": "ZZ"}),
       "E_INVALID_PARAM")
# 14) dry_run 只读零风险：sha 过期不阻断预览，降级为 note
f2 = P("dry.pas")
call("write_text_file", {"path": f2, "content": "l1\nl2\nl3\n"})
sha2 = call("read_text_lines", {"path": f2}).split("sha256:")[1].split(" ")[0]
open(f2, "wb").write(b"l1\nl2\nl3\nl4\n")   # 模拟他人改动
out = call("edit_file_lines", {"path": f2, "operation": "replace_lines", "start_line": 2,
                               "end_line": 2, "content": "L2", "expected_old": "l2",
                               "expected_sha256": sha2, "dry_run": True})
print(f"{'dry_run survives stale sha':<46} {'-':<22} "
      f"{'PASS' if ('expected_sha256 is stale' in out and 'DRY-RUN' in out and not out.startswith('[ERROR]')) else '**FAIL**'}")
# 15) 局部编辑不传 sha：他人改了别处也应成功，并保留他人改动
f3 = P("local.pas")
call("write_text_file", {"path": f3, "content": "aaa\nkeep\nzzz\n"})
open(f3, "wb").write(b"aaa\nkeep\nzzz\nadded-by-other\n")
out = call("regex_replace", {"path": f3, "pattern": "zzz", "replacement": "ZZZ",
                             "literal": True, "max_matches": 1})
print(f"{'local edit merges concurrent change':<46} {'-':<22} "
      f"{'PASS' if ('matches' in out and 'sha256:' in out and not out.startswith('[ERROR]')) else '**FAIL**'}")
final = open(f3, "rb").read().decode("utf-8", "replace")
print(f"{'  others change preserved':<46} {'-':<22} "
      f"{'PASS' if ('added-by-other' in final and 'ZZZ' in final) else '**FAIL**'}")
# 16) 并发安全不放松：真实写入仍严格校验 sha
out = call("edit_file_lines", {"path": f3, "operation": "replace_lines", "start_line": 1,
                               "end_line": 1, "content": "AAA", "expected_old": "aaa",
                               "expected_sha256": "deadbeefdeadbeef"})
print(f"{'write still strict on stale sha':<46} {'E_EXTERNAL_CHANGED':<22} "
      f"{'PASS' if 'E_EXTERNAL_CHANGED' in out else '**FAIL**'}")
# 17) 正常路径不应出现错误码
out = call("read_text_lines", {"path": f})
print(f"{'success path has no E_ code':<46} {'-':<22} {'PASS' if not out.startswith('[ERROR]') else '**FAIL**'}")

proc.kill()
