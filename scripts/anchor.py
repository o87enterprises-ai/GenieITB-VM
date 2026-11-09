#!/usr/bin/env python3
"""Out-of-band receipt anchor (EXT-04 / review F8).

  anchor.py write  <receipt.db> <label>   append a keyed anchor for the chain head
  anchor.py verify <receipt.db> <label>   check the db against its latest anchor

An anchor is one JSON line: {label, rows, head, at, mac}. mac = HMAC-SHA256 over
label|rows|head|at with a key the VM and the receipt-writing account cannot read.

Environment:
  ANCHOR_KEY_FILE   path to key file (mode 0600, outside the repo). Required.
  ANCHOR_FILE       append-only anchor log (default ~/.genieitb/anchors.jsonl).
                    Protect it: `sudo chattr +a` or place on a separate account/host.
  ANCHOR_PUSH_CMD   optional command run after write with the line on stdin, for a
                    remote append-only store (e.g. a transparency log). Failure = error.

Honest limit: a local file only helps if the attacker cannot write it. Put the key and
the anchor log behind a different privilege boundary than the receipt writer.
"""
import hashlib, hmac, importlib.util, json, os, stat, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("receipt4", os.path.join(HERE, "04-receipt.py"))
receipt = importlib.util.module_from_spec(spec); spec.loader.exec_module(receipt)

def fail(msg, code=1):
    print(f"anchor: {msg}", file=sys.stderr); sys.exit(code)

def load_key():
    p = os.environ.get("ANCHOR_KEY_FILE") or fail("ANCHOR_KEY_FILE not set", 2)
    try: st = os.stat(p)
    except OSError as e: fail(f"cannot read key: {e}", 2)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        fail(f"{p} must not be group/world accessible", 2)
    k = open(p, "rb").read().strip()
    if len(k) < 32: fail("key shorter than 32 bytes", 2)
    return k

def anchor_path():
    return os.environ.get("ANCHOR_FILE", os.path.expanduser("~/.genieitb/anchors.jsonl"))

def mac(key, label, rows, head, at):
    return hmac.new(key, f"{label}|{rows}|{head}|{at}".encode(), hashlib.sha256).hexdigest()

def chain_state(db):
    ok, msg = receipt.verify(db)
    if not ok: fail(f"chain does not verify: {msg}")
    # msg is "<n> entries, head <hash>"
    n, head = msg.split(" entries, head ")
    return int(n), head

def cmd_write(db, label):
    key = load_key(); rows, head = chain_state(db); at = int(time.time())
    line = json.dumps({"label": label, "rows": rows, "head": head, "at": at,
                       "mac": mac(key, label, rows, head, at)}, separators=(",", ":"))
    p = anchor_path(); os.makedirs(os.path.dirname(p), exist_ok=True, mode=0o700)
    with open(p, "a") as f: f.write(line + "\n")
    push = os.environ.get("ANCHOR_PUSH_CMD")
    if push and subprocess.run(push, shell=True, input=line.encode()).returncode != 0:
        fail("ANCHOR_PUSH_CMD failed; anchor is NOT durable off-host")
    print(f"anchored label={label} rows={rows} head={head}")

def cmd_verify(db, label):
    key = load_key(); rows, head = chain_state(db)
    best = None
    try: lines = open(anchor_path()).read().splitlines()
    except OSError as e: fail(f"cannot read anchor log: {e}", 2)
    for l in lines:
        try: a = json.loads(l)
        except ValueError: fail("anchor log has a malformed line (tampered anchor log)")
        if a.get("label") != label: continue
        if not hmac.compare_digest(a.get("mac", ""), mac(key, label, a["rows"], a["head"], a["at"])):
            fail(f"anchor for {label} at {a['at']} has a bad MAC (tampered anchor log)")
        if best is None or a["at"] >= best["at"]: best = a
    if best is None: fail(f"no anchor for label {label}", 2)
    if rows < best["rows"]: fail(f"TRUNCATED: db has {rows} rows, anchor says {best['rows']}")
    if rows == best["rows"] and head != best["head"]: fail("REWRITTEN: same row count, different head")
    # rows > anchored: allowed only if the anchored prefix is intact
    import sqlite3
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    r = c.execute("SELECT hash FROM chain WHERE n = (SELECT n FROM chain ORDER BY n LIMIT 1 OFFSET ?)",
                  (best["rows"] - 1,)).fetchone(); c.close()
    if not r or r[0] != best["head"]: fail("REWRITTEN: anchored head not present in chain")
    print(f"anchor OK label={label} rows={rows} anchored_rows={best['rows']}")

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("write", "verify"):
        fail("usage: anchor.py write|verify <receipt.db> <label>", 2)
    {"write": cmd_write, "verify": cmd_verify}[sys.argv[1]](sys.argv[2], sys.argv[3])
