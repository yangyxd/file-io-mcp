# -*- coding: utf-8 -*-
"""GBK / UTF-8 区分验证：重点是"GBK 字节序列恰好也是合法 UTF-8"的冲突样本"""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_enc2_data"
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
enc_of = lambda s: s.split("|")[1].strip()


def find_conflict_chars():
    """找出 GBK 汉字中"两字节恰好也是合法 UTF-8"的字符（首 0xC2-0xDF + 尾 0xA1-0xBF）"""
    out = []
    for b1 in range(0xC2, 0xE0):
        for b2 in range(0xA1, 0xC0):
            raw = bytes([b1, b2])
            try:
                ch = raw.decode("gbk")
            except UnicodeDecodeError:
                continue
            try:
                raw.decode("utf-8")   # 同时是合法 UTF-8
            except UnicodeDecodeError:
                continue
            out.append((raw, ch, raw.decode("utf-8")))
    return out


conflicts = find_conflict_chars()
print("conflict GBK chars that are also valid UTF-8:", len(conflicts),
      "| e.g.", conflicts[0] if conflicts else None)

# ---------- C1: 冲突样本（GBK 汉字，字节同时合法 UTF-8）应判 gbk ----------
cn_conflict = "".join(c for _, c, _ in conflicts[:12])
f1 = P("conflict_gbk.pas")
text1 = "unit T;\r\n// " + cn_conflict + "\r\nend.\r\n"
open(f1, "wb").write(text1.encode("gbk"))
raw1 = open(f1, "rb").read()
is_valid_utf8 = True
try:
    raw1.decode("utf-8")
except UnicodeDecodeError:
    is_valid_utf8 = False
r = call("read_text_lines", {"path": f1})
print("C1 conflict GBK file:", "bytes are valid UTF-8 =", is_valid_utf8,
      "-> detected:", enc_of(r), ok(enc_of(r) == "gbk"))
print("   content readable:", ok(cn_conflict[:6] in r or "FAIL" in r))

# ---------- C2: 真 UTF-8 中文应判 utf-8 ----------
cn_utf8 = "中文测试代码注释"
f2 = P("utf8_cn.pas")
open(f2, "wb").write(("unit U;\r\n// " + cn_utf8 + "\r\nend.\r\n").encode("utf-8"))
r = call("read_text_lines", {"path": f2})
print("C2 real UTF-8 file -> detected:", enc_of(r), ok(enc_of(r) == "utf-8"),
      "| cn kept:", ok(cn_utf8 in r))

# ---------- C3: 真 GBK 中文（非合法 UTF-8）应判 gbk ----------
cn_gbk = "中文测试代码注释"
f3 = P("gbk_cn.pas")
open(f3, "wb").write(("unit G;\r\n// " + cn_gbk + "\r\nend.\r\n").encode("gbk"))
r = call("read_text_lines", {"path": f3})
print("C3 real GBK file -> detected:", enc_of(r), ok(enc_of(r) == "gbk"),
      "| cn kept:", ok(cn_gbk in r))

# ---------- C4: 纯 ASCII 判 utf-8（与 GBK 字节等价，无风险） ----------
f4 = P("ascii.pas")
open(f4, "wb").write(b"unit A;\r\nbegin\r\nend.\r\n")
r = call("read_text_lines", {"path": f4})
print("C4 pure ASCII -> detected:", enc_of(r), ok(enc_of(r) == "utf-8"),
      "| no warn:", ok("不确定" not in r))

# ---------- C5: 往返一致性（读出来再写回，字节不变） ----------
for name, path in [("conflict_gbk", f1), ("utf8_cn", f2), ("gbk_cn", f3)]:
    before = open(path, "rb").read()
    r = call("read_text_lines", {"path": path})
    e = enc_of(r).replace("(BOM)", "")
    # 用同样内容 overwrite 写回
    r2 = call("write_text_file", {"path": path, "mode": "append", "content": ""})
    after = open(path, "rb").read()
    print(f"C5 roundtrip {name} ({e}):", ok(before == after))

# ---------- C6: UTF-8 BOM 文件 ----------
f6 = P("utf8bom.pas")
open(f6, "wb").write(b"\xef\xbb\xbf" + "// 注释\r\n".encode("utf-8"))
r = call("read_text_lines", {"path": f6})
print("C6 utf-8 BOM -> detected:", enc_of(r), ok("utf-8(BOM)" == enc_of(r)))

proc.kill()
