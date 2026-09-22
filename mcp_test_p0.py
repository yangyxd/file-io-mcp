# -*- coding: utf-8 -*-
"""P0 验证：编码/BOM 保持、逐行换行保留、原子写入、OCC 并发校验。通过 MCP stdio 协议调用"""
import subprocess, json, os, time, threading, queue

EXE = r"F:\Projects\Web\file-io-mcp\target\debug\file-io-mcp.exe"
TEST_DIR = r"F:\Projects\Web\file-io-mcp\mcp_test_p0_data"
os.makedirs(TEST_DIR, exist_ok=True)


def start():
    p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=0)
    time.sleep(0.4)
    send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1.0"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p


def send(p, msg):
    p.stdin.write(json.dumps(msg, ensure_ascii=False).encode('utf-8') + b'\n')
    p.stdin.flush()


def recv(p):
    return json.loads(p.stdout.readline())


def make_client():
    """模拟一个独立的 AI 客户端"""
    proc = start()
    state = {"id": 100}

    def call(name, args):
        state["id"] += 1
        send(proc, {"jsonrpc": "2.0", "id": state["id"], "method": "tools/call",
                    "params": {"name": name, "arguments": args}})
        r = recv(proc)
        if "result" in r and "content" in r["result"]:
            return "".join(c.get("text", "") for c in r["result"]["content"])
        if "error" in r:
            return "[ERROR] " + r["error"].get("message", "")
        return str(r)
    return proc, call


def show(t, s, n=700):
    print(f"\n===== {t} =====")
    print(s[:n])


P = lambda n: os.path.join(TEST_DIR, n).replace("\\", "/")
proc, call = make_client()

# ---------- 1. UTF-16LE 文件编辑后 BOM 保持 ----------
f16 = P("utf16.pas")
with open(f16, "wb") as f:
    f.write("﻿".encode("utf-16le") + "unit A;\r\nbegin\r\n  x := 1;\r\nend.\r\n".encode("utf-16le"))
show("1.1 读 UTF-16LE(应显示 utf-16le(BOM))", call("read_text_lines", {"path": f16}))
show("1.2 按行替换后写回", call("edit_file_lines", {
    "path": f16, "operation": "replace_lines", "start_line": 3, "end_line": 3,
    "content": "  x := 2;", "expected_old": "  x := 1;"}))
head = open(f16, "rb").read(4)
print("\n1.3 写回后文件头4字节:", head.hex(), "→ BOM 是否保留:", head[:2] == b"\xff\xfe")
show("1.4 再次读取(应仍是 utf-16le(BOM)，不是 gbk)", call("read_text_lines", {"path": f16}))

# ---------- 2. UTF-8 BOM 文件 ----------
f8 = P("utf8bom.pas")
with open(f8, "wb") as f:
    f.write(b"\xef\xbb\xbf" + "unit B;\r\nbegin\r\nend.\r\n".encode("utf-8"))
show("2.1 读 UTF-8 BOM", call("read_text_lines", {"path": f8}))
call("edit_file_lines", {"path": f8, "operation": "append_lines", "content": "// 追加一行"})
print("2.2 写回后是否有 UTF-8 BOM:", open(f8, "rb").read(3) == b"\xef\xbb\xbf")

# ---------- 3. 混合换行：局部编辑不影响其他行换行符 ----------
fm = P("mixed.pas")
with open(fm, "wb") as f:
    f.write(b"line1\r\nline2\nline3\r\nline4\n")
show("3.1 读混合换行文件", call("read_text_lines", {"path": fm}))
show("3.2 改第 3 行", call("edit_file_lines", {
    "path": fm, "operation": "replace_lines", "start_line": 3, "end_line": 3,
    "content": "line3-changed", "expected_old": "line3"}))
raw = open(fm, "rb").read()
print("3.3 文件字节:", raw)
print("3.4 是否统一为单一换行符(无 CRLF 残留):", b"\r\n" not in raw)

# ---------- 4. 末尾无换行的文件追加（保持现状：按主换行风格 join，末行不带换行符） ----------
fe = P("noeol.pas")
with open(fe, "wb") as f:
    f.write(b"a\r\nb")   # 末行无换行
call("edit_file_lines", {"path": fe, "operation": "append_lines", "content": "c"})
print("4.1 末尾无换行文件追加后:", open(fe, "rb").read())

# ---------- 5. expected_sha256 冲突拒绝 ----------
fs = P("occ.pas")
call("write_text_file", {"path": fs, "content": "1\n2\n3\n"})
r = call("read_text_lines", {"path": fs})
sha = r.split("sha256:")[1].split(" ")[0]
show("5.1 读取(取到 sha)", r)
show("5.2 用正确 sha 编辑", call("edit_file_lines", {
    "path": fs, "operation": "replace_lines", "start_line": 1, "end_line": 1,
    "content": "1-edited", "expected_old": "1", "expected_sha256": sha}))
show("5.3 用过期 sha 再编辑(应被拒绝)", call("edit_file_lines", {
    "path": fs, "operation": "replace_lines", "start_line": 2, "end_line": 2,
    "content": "2-edited", "expected_old": "2", "expected_sha256": sha}))
print("5.4 文件内容(第2行应未被改):", open(fs, "rb").read())

# ---------- 6. 并发：4 个独立 AI 进程同时改同一文件不同行 ----------
fc = P("concurrent.pas")
call("write_text_file", {"path": fc, "content": "\n".join(f"L{i}" for i in range(1, 21)) + "\n"})
clients = [make_client() for _ in range(4)]
procs = [c[0] for c in clients]
results = queue.Queue()

lines_to_edit = [(2, "A"), (7, "B"), (13, "C"), (19, "D")]


def worker(idx, ln, tag):
    _, c = clients[idx]
    try:
        r = c("edit_file_lines", {
            "path": fc, "operation": "replace_lines", "start_line": ln, "end_line": ln,
            "content": f"line{tag}", "expected_old": f"L{ln}"})
    except Exception as e:
        r = f"[EXC] {e}"
    results.put((tag, r))


ts = [threading.Thread(target=worker, args=(i, ln, tag)) for i, (ln, tag) in enumerate(lines_to_edit)]
for t in ts:
    t.start()
for t in ts:
    t.join()

while not results.empty():
    tag, r = results.get()
    print(f"\n6.{tag} 结果:", r[:160])

content = open(fc, "rb").read().decode()
print("\n6.5 四个修改是否都在:", all(f"line{t}" in content for _, t in lines_to_edit))
print("6.6 行数是否仍为 20:", len([l for l in content.split("\n") if l]) == 20)

# ---------- 7. 临时文件不残留 ----------
leftovers = [n for n in os.listdir(TEST_DIR) if "file-io-mcp" in n and n.endswith(".tmp")]
print("\n7.1 残留的临时文件:", leftovers)

for p in procs:
    p.kill()
proc.kill()
