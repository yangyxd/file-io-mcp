# -*- coding: utf-8 -*-
"""统计 tools/list 的 schema 体量（token 开销基线）"""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
time.sleep(0.4)


def send(msg):
    proc.stdin.write(json.dumps(msg, ensure_ascii=False).encode("utf-8") + b"\n")
    proc.stdin.flush()


def recv():
    return json.loads(proc.stdout.readline())


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "size", "version": "1.0"}}})
init = recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
r = recv()

tools = r["result"]["tools"]
total_desc = 0
total_schema = 0
rows = []
for t in tools:
    d = t.get("description", "") or ""
    props = (t.get("inputSchema") or {}).get("properties") or {}
    pdesc = 0
    pinfo = []
    for k, v in props.items():
        pd = v.get("description", "") or ""
        pdesc += len(pd)
        pinfo.append(f"{k}:{len(pd)}")
    schema_chars = len(json.dumps(t.get("inputSchema") or {}, ensure_ascii=False))
    total_desc += len(d) + pdesc
    total_schema += schema_chars
    rows.append((t["name"], len(d), pdesc, schema_chars, pinfo))

print(f"{'tool':<20} {'desc':>6} {'params':>7} {'schema':>7}")
for name, d, p, s, _ in sorted(rows, key=lambda x: -(x[1] + x[2])):
    print(f"{name:<20} {d:>6} {p:>7} {s:>7}")
print("-" * 44)
print(f"{'TOTAL':<20} {total_desc:>13} {total_schema:>7}")

instr = (init.get("result", {}).get("instructions") or "")
print(f"\ninstructions: {len(instr)} chars")
print(f"tools: {len(tools)}")
rough = (total_desc + total_schema + len(instr)) / 1.7
print(f"粗略 token 估算(中英混排 ~1.7 字符/token): {int(rough)}")
proc.kill()
