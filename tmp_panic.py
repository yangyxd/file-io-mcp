# -*- coding: utf-8 -*-
"""验证：工具内部 panic 被兜住，服务继续可用。用法: python tmp_panic.py <exe>"""
import subprocess, json, os, sys, time

exe = sys.argv[1]
WS = r"f:/App/file-io-mcp"

env = dict(os.environ)
env.pop("FILE_IO_ROOT", None)
env_p = dict(env)
env_p["FILE_IO_TEST_PANIC"] = "1"


def start(e):
    p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=0, env=e, cwd=WS)
    time.sleep(0.6)
    return p


def send(p, m):
    p.stdin.write(json.dumps(m, ensure_ascii=False).encode("utf-8") + b"\n")
    p.stdin.flush()


def recv(p):
    return json.loads(p.stdout.readline())


def init(p):
    send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "v", "version": "1"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})


_id = [0]


def call(p, name, args):
    _id[0] += 1
    send(p, {"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
             "params": {"name": name, "arguments": args}})
    r = recv(p)
    if "result" in r and "content" in r["result"]:
        return "".join(c.get("text", "") for c in r["result"]["content"])
    if "error" in r:
        return "[ERROR] " + r["error"].get("message", "")
    return str(r)


fails = []


def rep(label, ok, extra=""):
    print(("PASS " if ok else "**FAIL** ") + label + (" | " + str(extra)[:160] if extra else ""))
    if not ok:
        fails.append(label)


def line(s):
    return s.replace("\n", " | ")[:150]


print("=== exe: %s ===" % exe)

# ---------- 触发 panic ----------
p = start(env_p)
init(p)

r1 = call(p, "file_info", {"path": "README.md"})
rep("1 panic 被捕获，返回 E_PANIC 错误（不是断连）",
    r1.startswith("[ERROR]") and "E_PANIC" in r1 and "已捕获" in r1, line(r1))

rep("2 panic 后进程仍存活", p.poll() is None, "poll=%s" % p.poll())

r2 = call(p, "read_text_file", {"path": "README.md", "length": 20})
rep("3 panic 之后其他工具仍可用", not r2.startswith("[ERROR]") and "README.md" in r2, line(r2))

r3 = call(p, "file_info", {"path": "README.md"})
rep("4 同一工具再次触发仍稳定返回 E_PANIC", r3.startswith("[ERROR]") and "E_PANIC" in r3, line(r3))

r4 = call(p, "read_text_lines", {"path": "README.md", "limit": 3})
rep("5 多次 panic 后服务依然健康", not r4.startswith("[ERROR]") and "file-io" in r4.lower(), line(r4))

r5 = call(p, "list_files", {"path": "."})
rep("6 panic 后目录类工具仍可用", not r5.startswith("[ERROR]"), line(r5))

p.stdin.close()
try:
    p.wait(timeout=5)
except Exception:
    p.kill()
err = p.stderr.read().decode("utf-8", "replace")
print("---- STDERR ----")
print(err[:2000])
print("---- /STDERR ----")
rep("7 stderr 里留下了可定位的 panic 记录",
    "file_info" in err and ("panic" in err.lower() or "main.rs" in err), err.strip().splitlines()[-1][:150] if err.strip() else "<empty>")

# ---------- 对照：不触发 ----------
p2 = start(env)
init(p2)
r6 = call(p2, "file_info", {"path": "README.md"})
rep("8 对照：不触发时 file_info 正常", not r6.startswith("[ERROR]") and "README.md" in r6, line(r6))
p2.stdin.close()
try:
    p2.wait(timeout=5)
except Exception:
    p2.kill()

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
