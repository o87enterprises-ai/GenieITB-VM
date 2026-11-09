#!/usr/bin/env python3
"""Control validation for receipts and the host listener (GEN-05, GEN-11, GEN-19)."""
import importlib.util, os, shutil, socket, sqlite3, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

sup = load("sup", "05-supervisor.py")
receipt = sup.receipt
failures = 0
def check(name, ok):
    global failures
    print(("PASS: " if ok else "FAIL: ") + name)
    failures += 0 if ok else 1

tmp = tempfile.mkdtemp()
db, events, path = (os.path.join(tmp, n) for n in ("r.db", "events", "l.sock"))

# A real listener, driven by real sockets.
stop, ready = threading.Event(), threading.Event()
t = threading.Thread(target=sup.run_vsock_listener,
                     args=(sup.bind_listener(path), path, events, db, ready, stop), daemon=True)
t.start(); ready.wait(2)

def send(data, half_close=True):
    s = socket.socket(socket.AF_UNIX); s.settimeout(8); s.connect(path); s.sendall(data)
    if half_close: s.shutdown(socket.SHUT_WR)
    try: reply = s.recv(16)
    except OSError: reply = b""
    s.close(); return reply

check("complete line is committed and acked", send(b"DENY doc_agent one\n") == b"ack\n")
check("cut-off line is not acked", send(b"ALLOW doc_agent partial") == b"")
check("line that times out is not acked", send(b"ALLOW doc_agent slow", half_close=False) == b"")
check("oversized line is not acked", send(b"x" * 20000) == b"")
time.sleep(0.2); stop.set(); t.join(3)

details = [r[0] for r in sqlite3.connect(db).execute("SELECT detail FROM run_events ORDER BY seq")]
check("partial content never recorded as a line", not any(d.startswith("ALLOW doc_agent") for d in details))
check("each incomplete line recorded as TRUNCATION", sum(d.startswith("TRUNCATION") for d in details) == 3)
check("intact chain verifies", receipt.verify(db)[0])

def tampered(sql):
    copy = os.path.join(tmp, "copy.db"); shutil.copy(db, copy)
    c = sqlite3.connect(copy); c.execute(sql); c.commit(); c.close()
    return not receipt.verify(copy)[0]

check("edited run_events row is detected", tampered("UPDATE run_events SET detail='ALLOW forged' WHERE seq=1"))
check("deleted run_events row is detected", tampered("DELETE FROM run_events WHERE seq=1"))
check("extra run_events row is detected", tampered("INSERT INTO run_events (kind,detail,at) VALUES ('vsock','x',1)"))

env = dict(os.environ, ANCHOR_KEY_FILE=os.path.join(tmp, "key"), ANCHOR_FILE=os.path.join(tmp, "anchors"))
with open(env["ANCHOR_KEY_FILE"], "w") as f: f.write("k" * 48)
os.chmod(env["ANCHOR_KEY_FILE"], 0o600)
anchor = lambda *a: subprocess.run([sys.executable, "-B", os.path.join(HERE, "anchor.py"), *a, db, "t"],
                                   env=env, capture_output=True).returncode
check("anchor verifies", anchor("write") == 0 and anchor("verify") == 0)
with open(env["ANCHOR_FILE"], "a") as f: f.write("garbage\n")
check("malformed anchor line is rejected", anchor("verify") != 0)

shutil.rmtree(tmp)
print("==> RECORDS PASS" if not failures else "==> RECORDS FAILED")
sys.exit(1 if failures else 0)
