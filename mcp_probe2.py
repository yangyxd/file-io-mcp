# -*- coding: utf-8 -*-
"""Read-only behaviour probe: verify 3 description claims. Does not modify project code."""
import subprocess, json, os, time, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\release\file-io-mcp.exe"
D = r"F:\Projects\Web\file-io-mcp\mcp_probe2_data"
os.makedirs(D, exist_ok=True)
proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
time.sleep(0.4)


def send(m):
    proc.stdin.write(json.dumps(m, ensure_ascii=False).encode("utf-8") + b"\n")
    proc.stdin.flush()


def recv():
    return json.loads(proc.stdout.readline())


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "probe2", "version": "1.0"}}})
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


P = lambda n: os.path.join(D, n).replace("\\", "/")

print("=== 1) write_text_file mode=overwrite WITHOUT expected_sha256 ===")
f = P("ovr.txt")
call("write_text_file", {"path": f, "content": "v1\n"})
r = call("write_text_file", {"path": f, "content": "v2-no-sha\n"})  # no expected_sha256
print("result:", r.replace("\n", " ")[:150])
print("file now:", open(f, encoding="utf-8").read().strip())
print("=> claim 'expected_sha256 is REQUIRED for mode=overwrite' ENFORCED?",
      "NO - accepted without sha" if "ERROR" not in r else "YES")

print()
print("=== 2) text_search: does extension= un-skip HIDDEN files? ===")
hid = P(".hidden_probe.txt")
open(hid, "w", encoding="utf-8").write("NEEDLE_IN_HIDDEN\n")
vis = P("visible_probe.txt")
open(vis, "w", encoding="utf-8").write("NEEDLE_IN_VISIBLE\n")
r = call("text_search", {"path": P(""), "pattern": "NEEDLE_IN_", "mode": "literal",
                         "extension": "txt"})
print("with extension=txt only ->", r.replace("\n", " ")[:220])
print("hidden file searched?", "hidden_probe" in r)
r2 = call("text_search", {"path": P(""), "pattern": "NEEDLE_IN_", "mode": "literal",
                          "include": ["*.txt"]})
print("with include=*.txt      -> hidden searched?", "hidden_probe" in r2)
r3 = call("text_search", {"path": P(""), "pattern": "NEEDLE_IN_", "mode": "literal",
                          "skip_hidden": False})
print("with skip_hidden=false   -> hidden searched?", "hidden_probe" in r3)
r4 = call("text_search", {"path": P(""), "pattern": "NEEDLE_IN_", "mode": "literal",
                          "exclude": ["nothing*"]})
print("with exclude only        -> hidden searched?", "hidden_probe" in r4)

print()
print("=== 3) delete_file confirm=false output text ===")
f2 = P("del.txt")
call("write_text_file", {"path": f2, "content": "x\n"})
r = call("delete_file", {"path": f2})
print(r.replace("\n", " ")[:220])
proc.kill()
