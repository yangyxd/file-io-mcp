# -*- coding: utf-8 -*-
"""性能基准：大文件下各写/读工具的耗时（含 MCP 往返），用于评估新增防护的开销"""
import subprocess, json, os, time, sys, statistics

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_bench_data"
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
    "clientInfo": {"name": "bench", "version": "1.0"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

_id = [100]


def call(name, args):
    _id[0] += 1
    t0 = time.perf_counter()
    send({"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    r = recv()
    dt = (time.perf_counter() - t0) * 1000
    txt = "".join(c.get("text", "") for c in r.get("result", {}).get("content", []))
    if "error" in r:
        txt = "[ERROR] " + r["error"].get("message", "")
    return dt, txt


def bench(label, fn, runs=3):
    ts = []
    out = ""
    for _ in range(runs):
        dt, out = fn()
        ts.append(dt)
    print(f"{label:<52} {statistics.median(ts):8.1f} ms   (min {min(ts):.1f})")
    return out


P = lambda n: os.path.join(TEST_DIR, n).replace("\\", "/")


def make_file(name, size_mb, chinese=False, gbk=False):
    p = P(name)
    line = ("  // 这是中文注释行，用于测试编码检测与写回开销\r\n" if chinese
            else "  // a normal comment line for benchmarking purposes\r\n")
    data = line.encode("gbk" if gbk else "utf-8")
    with open(p, "wb") as f:
        written = 0
        while written < size_mb * 1024 * 1024:
            f.write(data)
            written += len(data)
    return p, os.path.getsize(p)


print("=" * 84)
print("文件准备")
tmp_pas = P("small.pas")
call("write_text_file", {"path": tmp_pas, "content": "unit A;\r\nbegin\r\nend.\r\n"})

for size_mb in (1, 5):
    p, n = make_file(f"ascii_{size_mb}mb.pas", size_mb)
    print(f"  ascii_{size_mb}mb.pas  {n/1024/1024:.1f} MB")
    bench(f"[{size_mb}MB ASCII] read_text_lines (只取10行)",
          lambda p=p: call("read_text_lines", {"path": p, "start_line": 1, "end_line": 10}))
    bench(f"[{size_mb}MB ASCII] read_text_file (只取1KB, 含sha)",
          lambda p=p: call("read_text_file", {"path": p, "length": 1024}))
    bench(f"[{size_mb}MB ASCII] edit_file_lines (改1行)",
          lambda p=p: call("edit_file_lines", {
              "path": p, "operation": "replace_lines", "start_line": 1, "end_line": 1,
              "content": "  // changed", "expected_old": "  // a normal comment line for benchmarking purposes"}))
    bench(f"[{size_mb}MB ASCII] write_text_file overwrite (1KB内容)",
          lambda p=p: call("write_text_file", {"path": p, "content": "unit X;\r\nend.\r\n"}))
    # 之后文件被 overwrite 成小文件，重新生成
    make_file(f"ascii_{size_mb}mb.pas", size_mb)

# GBK 中文大文件：测编码打分开销
p, n = make_file("gbk_cn_5mb.pas", 5, chinese=True, gbk=True)
print(f"\n  gbk_cn_5mb.pas  {n/1024/1024:.1f} MB (GBK 中文)")
bench("[5MB GBK中文] read_text_lines (只取10行)",
      lambda: call("read_text_lines", {"path": p, "start_line": 1, "end_line": 10}))
bench("[5MB GBK中文] edit_file_lines (改1行)",
      lambda: call("edit_file_lines", {
          "path": p, "operation": "replace_lines", "start_line": 1, "end_line": 1,
          "content": "  // 改过了", "expected_old": "  // 这是中文注释行，用于测试编码检测与写回开销"}))

# 小文件（真实 .pas 规模）基线
p, n = make_file("typical.pas", 0, chinese=True)
with open(p, "wb") as f:
    f.write(("unit T;\r\n" + "  // line\r\n" * 200 + "end.\r\n").encode("gbk"))
print(f"\n  typical.pas  {os.path.getsize(p)} B (真实 Delphi 单元规模)")
bench("[60KB GBK] read_text_lines 全量",
      lambda: call("read_text_lines", {"path": p, "start_line": 1, "end_line": 50}))
bench("[60KB GBK] edit_file_lines 改1行",
      lambda: call("edit_file_lines", {
          "path": p, "operation": "replace_lines", "start_line": 2, "end_line": 2,
          "content": "  // changed", "expected_old": "  // line"}))
bench("[60KB GBK] regex_replace",
      lambda: call("regex_replace", {"path": p, "pattern": "changed",
                                     "replacement": "changed2", "max_matches": 5}))

proc.kill()
