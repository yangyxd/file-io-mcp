# -*- coding: utf-8 -*-
"""备份/回滚验证：写前备份、undo 回滚、外部改动拒绝、自动与手动清理"""
import subprocess, json, os, time, sys, shutil

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

EXE = sys.argv[1] if len(sys.argv) > 1 else r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_bak_data"
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
# 备份现在放在 MCP 工具自身目录下（不污染项目），目录名 = <文件名>-<绝对路径hash16>
BAK_DIR = os.path.join(os.path.dirname(os.path.abspath(EXE)), ".file-io-mcp-backups")

# 清理上次运行残留的备份，保证计数断言稳定
TEST_FILES = ("a.pas", "b.pas", "c.pas", "d.pas", "same.pas")
if os.path.isdir(BAK_DIR):
    for d in os.listdir(BAK_DIR):
        if d.split("-")[0] in TEST_FILES:
            shutil.rmtree(os.path.join(BAK_DIR, d), ignore_errors=True)


def bak_dir_for(fpath):
    """按目标文件绝对路径定位其备份目录（前缀匹配文件名，后缀匹配 hash）"""
    name = os.path.basename(fpath)
    if not os.path.isdir(BAK_DIR):
        return None
    for d in os.listdir(BAK_DIR):
        if d.startswith(name + "-"):
            return os.path.join(BAK_DIR, d)
    return None


def count_baks(name):
    d = bak_dir_for(P(name))
    if not d or not os.path.isdir(d):
        return 0
    return len([f for f in os.listdir(d) if f.endswith(".bak")])


# ---------- B1: 覆盖写产生备份，且标记 undoable ----------
f = P("a.pas")
call("write_text_file", {"path": f, "content": "v1\n"})
r = call("write_text_file", {"path": f, "content": "v2\n"})
print("B1 overwrite marks undoable:", ok("undoable" in r), "| backups:", count_baks("a.pas"),
      ok(count_baks("a.pas") == 1))

# ---------- B2: list ----------
r = call("manage_backups", {"path": f, "action": "list"})
print("B2 list:", ok("1 backups" in r and "write_text_file" in r))

# ---------- B3: undo 回滚 ----------
r = call("manage_backups", {"path": f, "action": "undo"})
content = open(f, "rb").read()
print("B3 undo:", ok(open(f, 'rb').read() == b"v1\n"), "| content:", content,
      "| undoable snapshot kept:", ok(count_baks("a.pas") >= 1))

# ---------- B4: undo 本身可撤销（回滚前快照） ----------
r = call("manage_backups", {"path": f, "action": "undo"})
print("B4 undo again (revert the undo):", open(f, "rb").read(),
      ok(open(f, 'rb').read() == b"v2\n"))

# ---------- B5: 文件在备份之后被外部改动 → 默认拒绝回滚 ----------
call("write_text_file", {"path": f, "content": "v3\n"})
open(f, "wb").write(b"external-change\n")   # 模拟其他程序/AI 改动
r = call("manage_backups", {"path": f, "action": "undo"})
print("B5 refuse undo after external change:", ok("E_EXTERNAL_CHANGED" in r))
r = call("manage_backups", {"path": f, "action": "undo", "force": True})
print("B5 force undo:", ok("ERROR" not in r), "| content:", open(f, "rb").read())

# ---------- B6: 硬链接零拷贝（备份与目标共用 inode 时不影响正确性） ----------
f2 = P("b.pas")
call("write_text_file", {"path": f2, "content": "line1\nline2\n"})
before_sha = None
r = call("read_text_lines", {"path": f2})
call("edit_file_lines", {"path": f2, "operation": "replace_lines",
                         "start_line": 1, "end_line": 1, "content": "LINE1",
                         "expected_old": "line1"})
r = call("manage_backups", {"path": f2, "action": "undo"})
print("B6 edit then undo:", open(f2, "rb").read(), ok(open(f2, 'rb').read() == b"line1\nline2\n"))

# ---------- B7: 删除后可恢复 ----------
f3 = P("c.pas")
call("write_text_file", {"path": f3, "content": "important\n"})
r = call("delete_file", {"path": f3})
print("B7a delete without confirm is refused:",
      ok(os.path.exists(f3) and "E_INVALID_PARAM" in r and "confirm=true" in r), "|", r.splitlines()[0][:70])
r = call("delete_file", {"path": f3, "confirm": True})
print("B7b delete marks undoable:", ok("undoable" in r), "| exists:", ok(not os.path.exists(f3)))
r = call("manage_backups", {"path": f3, "action": "undo"})
print("   undo restores deleted file:", ok(os.path.exists(f3) and open(f3, "rb").read() == b"important\n"))

# ---------- B8: 自动清理（超过 10 份） ----------
f4 = P("d.pas")
call("write_text_file", {"path": f4, "content": "0\n"})
for i in range(15):
    call("write_text_file", {"path": f4, "content": f"{i+1}\n"})
n = count_baks("d.pas")
print("B8 auto trim keeps <=10:", n, ok(n == 10))

# ---------- B9: 手动 clean ----------
r = call("manage_backups", {"path": f4, "action": "clean", "keep": 3})
n = count_baks("d.pas")
print("B9 clean keep=3:", r.split("|")[1].strip() if "|" in r else r, ok(n == 3))
r = call("manage_backups", {"path": f4, "action": "clean", "keep": 0})
n = count_baks("d.pas")
print("B9b clean keep=0:", ok(n == 0), "| empty dir removed:",
      ok(not os.path.isdir(bak_dir_for(P("d.pas")) or "")))

# ---------- B10: 项目目录完全干净（备份不在项目里） ----------
r = call("list_files", {"path": TEST_DIR, "recursive": True})
print("B10 list_files hides backups dir:", ok(".file-io-mcp-backups" not in r))
r = call("text_search", {"path": TEST_DIR, "pattern": "v1", "recursive": True})
print("B10b text_search hides backups:", ok(".file-io-mcp-backups" not in r))
in_project = any(".file-io-mcp" in x for x in os.listdir(TEST_DIR))
print("B10c project dir has no backup dir:", ok(not in_project),
      "| entries:", sorted(os.listdir(TEST_DIR)))

# ---------- B11: 备份位于工具自身目录，且目录名带 文件名+hash ----------
d = bak_dir_for(P("a.pas"))
print("B11 backup under tool dir:", ok(d is not None and os.path.dirname(d) == BAK_DIR),
      "| dir name:", os.path.basename(d) if d else None)

# ---------- B12: 同名文件不同目录 → 备份互不串号 ----------
d1, d2 = P("same.pas"), os.path.join(TEST_DIR, "sub", "same.pas").replace("\\", "/")
os.makedirs(os.path.dirname(d2), exist_ok=True)
call("write_text_file", {"path": d1, "content": "one\n"})
call("write_text_file", {"path": d2, "content": "two\n"})
call("write_text_file", {"path": d1, "content": "one-v2\n"})
call("write_text_file", {"path": d2, "content": "two-v2\n"})
r1 = call("manage_backups", {"path": d1, "action": "list"})
r2 = call("manage_backups", {"path": d2, "action": "list"})
# 服务端按"文件名 + 绝对路径 hash"分区：同名不同目录应产生两个独立备份目录
same_dirs = [x for x in os.listdir(BAK_DIR) if x.startswith("same.pas-")]
print("B12 same-name files isolated:",
      ok(len(same_dirs) == 2 and "1 backups" in r1 and "1 backups" in r2),
      "| dirs:", sorted(same_dirs))
call("manage_backups", {"path": d1, "action": "undo"})
call("manage_backups", {"path": d2, "action": "undo"})
print("    undo each:", open(d1, "rb").read(), open(d2, "rb").read(),
      ok(open(d1, "rb").read() == b"one\n" and open(d2, "rb").read() == b"two\n"))

# ---------- B13: 相对路径与绝对路径指向同一份备份（路径归一化） ----------
rel = "mcp_test_bak_data/a.pas"     # 相对 workspace 根，服务端会 resolve 成绝对路径
ra = call("manage_backups", {"path": f, "action": "list"})
rb = call("manage_backups", {"path": rel, "action": "list"})
na = ra.split("|")[1].strip() if "|" in ra else ra
nb = rb.split("|")[1].strip() if "|" in rb else rb
print("B13 relative == absolute backup set:", ok(na == nb and "ERROR" not in rb),
      "|", na, "/", nb)

# ---------- B14: 磁盘上确认：备份目录未出现在项目里，且工具目录下有对应 key ----------
print("B14 project dir final:", sorted(os.listdir(TEST_DIR)))
print("    backup root:", BAK_DIR, "| entries:",
      len(os.listdir(BAK_DIR)) if os.path.isdir(BAK_DIR) else 0)

proc.kill()
