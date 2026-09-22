# -*- coding: utf-8 -*-
"""二进制写入护栏验证：expected_hex 写前校验、dry_run HEX diff、replace/insert 越界报错；
以及 text_search 截断标注（matches(truncated)）。"""
import subprocess, json, os, time, sys, shutil

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_bin_data"
shutil.rmtree(TEST_DIR, ignore_errors=True)
os.makedirs(TEST_DIR, exist_ok=True)

proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, bufsize=0)
time.sleep(0.4)

send = lambda m: (proc.stdin.write(json.dumps(m, ensure_ascii=False).encode("utf-8") + b"\n"),
                  proc.stdin.flush())
recv = lambda: json.loads(proc.stdout.readline())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "bin", "version": "1.0"}}})
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
failures = []


def check(label, passed, extra=""):
    print(f"{label}: {ok(passed)}{(' | ' + extra) if extra else ''}")
    if not passed:
        failures.append(label)


def setup(name, data):
    with open(P(name), "wb") as f:
        f.write(data)
    return P(name)


def read(name):
    with open(P(name), "rb") as f:
        return f.read()


BASE = bytes(range(16))          # 00 01 02 ... 0F

# ---------- B1: expected_hex 匹配 → 正常写入 ----------
f = setup("a.bin", BASE)
r = call("write_binary_file", {"path": f, "mode": "replace", "offset": 4, "replace_length": 4,
                               "hex_data": "AABBCCDD", "expected_hex": "04 05 06 07"})
check("B1 expected_hex match then write",
      "OK" in r and read("a.bin") == BASE[:4] + bytes([0xAA, 0xBB, 0xCC, 0xDD]) + BASE[8:],
      r.splitlines()[0][:70])

# ---------- B2: expected_hex 不匹配 → 拒绝且不落盘 ----------
before = read("a.bin")
r = call("write_binary_file", {"path": f, "mode": "replace", "offset": 4, "replace_length": 4,
                               "hex_data": "11121314", "expected_hex": "04 05 06 08"})
check("B2 expected_hex mismatch rejected",
      "E_GUARD_MISMATCH" in r and "实际字节" in r and read("a.bin") == before,
      r.splitlines()[0][:70])

# ---------- B3: expected_hex 宽松格式（0x / 冒号 / 换行 / 小写） ----------
r = call("write_binary_file", {"path": f, "mode": "replace", "offset": 0, "replace_length": 2,
                               "hex_data": "0102", "expected_hex": "0x00:01"})
check("B3 expected_hex flexible separators", "OK" in r and read("a.bin")[:2] == bytes([1, 2]),
      r.splitlines()[0][:70])

# ---------- B4: expected_hex 各 mode ----------
f2 = setup("b.bin", BASE)
r = call("write_binary_file", {"path": f2, "mode": "overwrite", "hex_data": "0F0E",
                               "expected_hex": "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"})
check("B4a overwrite guards whole file", "OK" in r and read("b.bin") == b"\x0f\x0e",
      r.splitlines()[0][:60])

f3 = setup("c.bin", BASE)
r = call("write_binary_file", {"path": f3, "mode": "append", "hex_data": "FF",
                               "expected_hex": "0E 0F"})
check("B4b append guards tail", "OK" in r and read("c.bin") == BASE + b"\xff",
      r.splitlines()[0][:60])

f4 = setup("d.bin", BASE)
r = call("write_binary_file", {"path": f4, "mode": "insert", "offset": 2, "hex_data": "FE",
                               "expected_hex": "02 03"})
check("B4c insert guards following bytes", "OK" in r and read("d.bin") == BASE[:2] + b"\xfe" + BASE[2:],
      r.splitlines()[0][:60])

f5 = setup("e.bin", BASE)
r = call("write_binary_file", {"path": f5, "mode": "insert", "offset": 2, "hex_data": "FE",
                               "expected_hex": "99 98"})
check("B4d insert mismatch rejected", "E_GUARD_MISMATCH" in r and read("e.bin") == BASE)

# ---------- B5: dry_run 只预览不落盘 ----------
f6 = setup("f.bin", BASE)
r = call("write_binary_file", {"path": f6, "mode": "replace", "offset": 4, "replace_length": 4,
                               "hex_data": "AABBCCDD", "dry_run": True})
check("B5a dry_run shows diff without writing",
      "DRY-RUN" in r and "差异窗口" in r and "sha256:" in r and read("f.bin") == BASE,
      r.splitlines()[0].strip()[:78])
check("B5b dry_run diff window content", "@00000000" in r and "04 05" in r and "AA BB" in r)

r = call("write_binary_file", {"path": f6, "mode": "overwrite", "hex_data": bytes(BASE).hex(),
                               "dry_run": True})
check("B5c dry_run identical content reports 无变化", "内容无变化" in r and read("f.bin") == BASE)

# ---------- B6: 越界显式报错（不再静默截断） ----------
r = call("write_binary_file", {"path": f6, "mode": "replace", "offset": 10, "replace_length": 10,
                               "hex_data": "AA"})
check("B6a replace out of range rejected",
      "[ERROR]" in r and "越界" in r and read("f.bin") == BASE, r.splitlines()[0][:70])
r = call("write_binary_file", {"path": f6, "mode": "insert", "offset": 100, "hex_data": "AA"})
check("B6b insert offset out of range rejected",
      "[ERROR]" in r and "超出文件大小" in r and read("f.bin") == BASE, r.splitlines()[0][:70])
r = call("write_binary_file", {"path": f6, "mode": "replace", "offset": 100, "replace_length": 1,
                               "hex_data": "AA"})
check("B6c replace offset out of range rejected", "[ERROR]" in r and read("f.bin") == BASE)

# ---------- B7: expected_hex 解析错误 ----------
r = call("write_binary_file", {"path": f6, "hex_data": "AA", "expected_hex": "ABC"})
check("B7a odd-length expected_hex rejected",
      "E_INVALID_PARAM" in r and "奇数" in r and read("f.bin") == BASE)
r = call("write_binary_file", {"path": f6, "hex_data": "AA", "expected_hex": "ZZ"})
check("B7b illegal chars in expected_hex rejected", "E_INVALID_PARAM" in r)

# ---------- B8: 常规写入/读取回归 ----------
f7 = P("g.bin")
r = call("write_binary_file", {"path": f7, "mode": "overwrite", "hex_data": "48656C6C6F"})
check("B8a overwrite ok", "OK" in r and read("g.bin") == b"Hello", r.splitlines()[0][:60])
r = call("write_binary_file", {"path": f7, "mode": "append", "hex_data": "21"})
check("B8b append ok", "OK" in r and read("g.bin") == b"Hello!")
r = call("write_binary_file", {"path": f7, "mode": "insert", "offset": 0, "hex_data": "3E"})
check("B8c insert ok", "OK" in r and read("g.bin") == b">Hello!")
r = call("write_binary_file", {"path": f7, "mode": "replace", "offset": 0, "replace_length": 1,
                               "hex_data": "3C"})
check("B8d replace ok", "OK" in r and read("g.bin") == b"<Hello!")
r = call("write_binary_file", {"path": f7, "mode": "bogus", "hex_data": "00"})
check("B8e bad mode message kept", "不支持的模式" in r)
r = call("read_binary_file", {"path": f7})
check("B8f read_binary_file still works", "sha256:" in r and "3C" in r)

# ---------- B9: text_search 截断标注 ----------
f8 = P("s.txt")
call("write_text_file", {"path": f8, "content": "hit\nhit\nhit\nhit\nhit\n"})
r = call("text_search", {"path": f8, "pattern": "hit", "max_results": 2})
check("B9a truncated label", "2/5 matches(truncated)" in r and "命中过多" in r,
      r.splitlines()[0].strip()[:78])
r = call("text_search", {"path": f8, "pattern": "hit", "max_results": 50})
check("B9b no-truncated label unchanged", "5 matches" in r and "truncated" not in r,
      r.splitlines()[0].strip()[:78])

proc.stdin.close()
proc.wait(timeout=5)
shutil.rmtree(TEST_DIR, ignore_errors=True)

print(f"\n二进制/截断测试完成：{'全部通过' if not failures else '失败 ' + str(len(failures)) + ' 项: ' + ', '.join(failures)}")
sys.exit(1 if failures else 0)
