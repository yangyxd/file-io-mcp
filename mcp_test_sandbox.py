# -*- coding: utf-8 -*-
"""沙箱（FILE_IO_ROOT）路径判定验证：
- 放行：根目录内路径的大小写差异、8.3 短名、`sub/..` 写法、新建文件（不存在的嵌套路径）
- 拦截：根目录之外、`..` 上跳逃逸、经不存在目录上跳、junction/符号链接指向根外
- 一致性：同一文件的不同写法解析为同一条规范路径（备份分区/指纹不分裂）
"""
import subprocess, json, os, time, sys, shutil, ctypes
import ctypes.wintypes as wt

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "mcp_test_sb_data")
OUTSIDE = os.path.join(BASE, "mcp_test_sb_outside")

ok = lambda b: "PASS" if b else "**FAIL**"
failures = []


def report(label, passed, extra=""):
    print(f"{label}: {ok(passed)}{(' | ' + extra) if extra else ''}")
    if not passed:
        failures.append(label)


shutil.rmtree(ROOT, ignore_errors=True)
shutil.rmtree(OUTSIDE, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)
os.makedirs(OUTSIDE, exist_ok=True)
with open(os.path.join(ROOT, "m.txt"), "w", encoding="utf-8") as f:
    f.write("hello\n")
with open(os.path.join(OUTSIDE, "o.txt"), "w", encoding="utf-8") as f:
    f.write("outside\n")

# 长目录名 → 用 GetShortPathNameW 取真实 8.3 短名
LONG_DIR = os.path.join(ROOT, "very_long_directory_name_for_shortname_test")
os.makedirs(LONG_DIR, exist_ok=True)
with open(os.path.join(LONG_DIR, "f.txt"), "w", encoding="utf-8") as f:
    f.write("shortname\n")
_get_short = ctypes.windll.kernel32.GetShortPathNameW
_get_short.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
_buf = ctypes.create_unicode_buffer(1024)
_get_short(LONG_DIR, _buf, 1024)
SHORT_DIR = _buf.value

# junction：ROOT\link -> OUTSIDE（模拟链接逃逸；junction 不需要管理员权限）
subprocess.run(["cmd", "/c", "mklink", "/J", os.path.join(ROOT, "link"), OUTSIDE], capture_output=True)

env = dict(os.environ)
env["FILE_IO_ROOT"] = ROOT
proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, bufsize=0, env=env)
time.sleep(0.4)

send = lambda m: (proc.stdin.write(json.dumps(m, ensure_ascii=False).encode("utf-8") + b"\n"),
                  proc.stdin.flush())
recv = lambda: json.loads(proc.stdout.readline())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "sandbox", "version": "1.0"}}})
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


def check_read(label, path, should_allow):
    r = call("read_text_file", {"path": path})
    allowed = "sha256" in r
    report(label, allowed == should_allow, f"allowed={allowed}" + ("" if allowed == should_allow
                                                                 else " RAW=" + r.splitlines()[0][:70]))


slash = lambda p: p.replace("\\", "/")

# 只把盘符改成小写（换盘符属于真的越界，不能用来测大小写）
_drive = os.path.splitdrive(ROOT)[0]                     # 例如 'F:'
_lower_drive = _drive.lower() + slash(ROOT)[len(_drive):]  # 例如 'f:/Projects/...'

# ---------- 放行：根目录内，写法不同 ----------
check_read("S1 exact case allowed", slash(os.path.join(ROOT, "m.txt")), True)
check_read("S2 lowercase drive allowed", _lower_drive + "/m.txt", True)
check_read("S3 lowercase dir segments allowed",
           slash(os.path.join(ROOT, "m.txt")).lower(), True)
check_read("S4 8.3 short name allowed", slash(os.path.join(SHORT_DIR, "f.txt")), True)
check_read("S5 dotdot inside root allowed",
           slash(os.path.join(ROOT, "sub", "..", "m.txt")), True)

# ---------- 拦截：越界与链接逃逸 ----------
check_read("S6 outside root denied", "C:/Windows/win.ini", False)
check_read("S7 dotdot escape denied", slash(ROOT) + "/../../Windows/win.ini", False)
check_read("S8 escape via nonexistent dir denied",
           slash(ROOT) + "/notexist/../../Windows/win.ini", False)
check_read("S9 junction escape denied", slash(os.path.join(ROOT, "link", "o.txt")), False)
check_read("S10 short-name outside denied",
           slash(_get_short(r"C:\Windows", _buf, 1024) and _buf.value) + "/win.ini", False)

# 目录形式列出链接目标也应被拒
r = call("list_files", {"path": slash(os.path.join(ROOT, "link")), "recursive": False})
report("S11 junction dir listing denied", "超出允许的根目录" in r, r.splitlines()[0][:60])

# ---------- 新建文件：不存在的嵌套路径 + 小写盘符 ----------
newp = _lower_drive + "/newdir/deep/n.txt"
r = call("write_text_file", {"path": newp, "content": "created\n"})
report("S12 create nested file via lowercase path",
       "OK" in r and os.path.exists(os.path.join(ROOT, "newdir", "deep", "n.txt")),
       r.splitlines()[0][:70])
r = call("read_text_file", {"path": slash(os.path.join(ROOT, "newdir", "deep", "n.txt"))})
report("S13 read back created file", "created" in r)

# 越界写入同样必须被拒
r = call("write_text_file", {"path": slash(OUTSIDE) + "/evil.txt", "content": "x\n"})
report("S14 outside write denied",
       "超出允许的根目录" in r and not os.path.exists(os.path.join(OUTSIDE, "evil.txt")))

# ---------- 路径写法归一：同一文件不同写法 → 同一条规范路径 ----------
a = call("file_info", {"path": slash(os.path.join(ROOT, "m.txt"))}).split("|")[0].strip()
b = call("file_info", {"path": slash(os.path.join(ROOT, "m.txt")).lower()}).split("|")[0].strip()
report("S15 canonical path stable across spellings", a == b and a != "", a[:64])

proc.stdin.close()
proc.wait(timeout=5)
subprocess.run(["cmd", "/c", "rmdir", os.path.join(ROOT, "link")], capture_output=True)
shutil.rmtree(ROOT, ignore_errors=True)
shutil.rmtree(OUTSIDE, ignore_errors=True)

print(f"\n沙箱测试完成：{'全部通过' if not failures else '失败 ' + str(len(failures)) + ' 项: ' + ', '.join(failures)}")
sys.exit(1 if failures else 0)
