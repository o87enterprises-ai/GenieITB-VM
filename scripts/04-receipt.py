#!/usr/bin/env python3
"""Phase 4 receipt: hash-chained SQLite, byte-compatible with ~/MonkeyITM-VM/log.

chain_hash matches eventlog::chain_hash exactly:
    sha256(prev || "\n" || kind || "\n" || payload)
first entry's prev is 64 zeros (CHAIN_GENESIS).
"""
import argparse, hashlib, json, sqlite3, sys, time

CHAIN_GENESIS = "0" * 64

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS intents (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL, action TEXT NOT NULL, params_json TEXT NOT NULL,
    justification TEXT, received_at INTEGER NOT NULL,
    agent TEXT NOT NULL DEFAULT 'root'
);
CREATE TABLE IF NOT EXISTS verdicts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    intent_id TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL,
    token TEXT, decided_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS escalations (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    intent_id TEXT NOT NULL, requested_at INTEGER NOT NULL,
    resolved_at INTEGER, decision TEXT
);
CREATE TABLE IF NOT EXISTS results (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    intent_id TEXT NOT NULL, result_json TEXT NOT NULL, recorded_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, detail TEXT NOT NULL, at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS job_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,
    detail TEXT NOT NULL, at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chain (
    n INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, ref_seq INTEGER NOT NULL, payload TEXT NOT NULL,
    prev TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intents_id ON intents(id);
CREATE INDEX IF NOT EXISTS idx_results_intent_id ON results(intent_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_intent_id ON verdicts(intent_id);
CREATE INDEX IF NOT EXISTS idx_escalations_intent_id ON escalations(intent_id);
"""

def chain_hash(prev, kind, payload):
    h = hashlib.sha256()
    h.update(prev.encode());  h.update(b"\n")
    h.update(kind.encode());  h.update(b"\n")
    h.update(payload.encode())
    return h.hexdigest()

def open_db(path):
    conn = sqlite3.connect(path, isolation_level=None)
    conn.executescript(SCHEMA)
    return conn

def append_run_event(db_path, kind, detail, at=None):
    at = int(time.time()) if at is None else int(at)
    payload = json.dumps([kind, detail, at], separators=(",", ":"), ensure_ascii=False)
    conn = open_db(db_path)
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("INSERT INTO run_events (kind, detail, at) VALUES (?,?,?)",
                    (kind, detail, at))
        seq = cur.lastrowid
        row = cur.execute("SELECT hash FROM chain ORDER BY n DESC LIMIT 1").fetchone()
        prev = row[0] if row else CHAIN_GENESIS
        h = chain_hash(prev, "run_event", payload)
        cur.execute("INSERT INTO chain (kind, ref_seq, payload, prev, hash) VALUES (?,?,?,?,?)",
                    ("run_event", seq, payload, prev, h))
        cur.execute("COMMIT")
        return seq, h
    except Exception:
        try: conn.execute("ROLLBACK")
        except Exception: pass
        raise
    finally:
        conn.close()

def verify(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        prev, n = CHAIN_GENESIS, 0
        for kind, ref_seq, payload, stored_prev, stored_hash in conn.execute(
                "SELECT kind, ref_seq, payload, prev, hash FROM chain ORDER BY n"):
            if stored_prev != prev:
                return False, f"chain[{n}] prev mismatch"
            if chain_hash(prev, kind, payload) != stored_hash:
                return False, f"chain[{n}] hash mismatch"
            prev = stored_hash
            n += 1
        return True, f"{n} entries, head {prev}"
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--kind", default="vsock")
    a.add_argument("--detail", required=True)
    sub.add_parser("verify")
    args = ap.parse_args()
    if args.cmd == "append":
        seq, h = append_run_event(args.db, args.kind, args.detail)
        print(f"appended seq={seq} hash={h}")
    else:
        ok, msg = verify(args.db)
        print(("OK: " if ok else "BROKEN: ") + msg)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
