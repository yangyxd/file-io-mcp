# -*- coding: utf-8 -*-
"""Dump tools/list descriptions + instructions for review (temporary, read-only analysis)."""
import subprocess, json, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\release\file-io-mcp.exe"
proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


def send(msg):
    proc.stdin.write(json.dumps(msg, ensure_ascii=False).encode("utf-8") + b"\n")
    proc.stdin.flush()


def recv():
    return json.loads(proc.stdout.readline())


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "dump", "version": "1.0"}}})
init = recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
r = recv()
tools = r["result"]["tools"]

instr = init.get("result", {}).get("instructions") or ""
print("=" * 100)
print(f"### INSTRUCTIONS ({len(instr)} chars)")
print("=" * 100)
print(instr)
print()

rows = []
for t in tools:
    d = t.get("description", "") or ""
    props = (t.get("inputSchema") or {}).get("properties") or {}
    req = (t.get("inputSchema") or {}).get("required") or []
    ptotal = 0
    plist = []
    for k, v in props.items():
        pd = v.get("description", "") or ""
        ptotal += len(pd)
        mark = "*" if k in req else " "
        plist.append((k, mark, len(pd), pd))
    rows.append((t["name"], len(d), ptotal, d, plist))

rows.sort(key=lambda x: -(x[1] + x[2]))
for name, dl, pt, d, plist in rows:
    print("=" * 100)
    print(f"### TOOL {name}  (desc {dl} chars, param-desc {pt} chars, total {dl + pt})")
    print("=" * 100)
    print(d)
    print("-" * 40)
    for k, mark, n, pd in sorted(plist, key=lambda x: -x[2]):
        print(f"  - {mark}{k} ({n}): {pd}")
    print()

print("=" * 100)
print("### SUMMARY")
td = tp = 0
for name, dl, pt, _, _ in rows:
    td += dl
    tp += pt
    print(f"{name:<22} {dl:>6} {pt:>6} {dl + pt:>6}")
print("-" * 44)
print(f"{'TOTAL':<22} {td:>6} {tp:>6} {td + tp:>6}")
print(f"instructions: {len(instr)}")
print(f"GRAND TOTAL (resident): {td + tp + len(instr)}")
proc.kill()
