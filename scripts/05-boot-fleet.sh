#!/usr/bin/env bash
# One microVM per agent, real agents, real image. JAIL=1 runs each VM under the jailer with its
# own uid (needs sudo). `kill` lowers the fleet tripwire so the run's three denials trip it.
#   usage: 05-boot-fleet.sh [default|kill]
set -uo pipefail
MODE="${1:-default}"
case "$MODE" in default) TRIP=4; WANT=0;; kill) TRIP=3; WANT=3;; *) echo "usage: $0 [default|kill]" >&2; exit 2;; esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FC="$ROOT/bin/firecracker"; KERNEL="$ROOT/kernel/vmlinux.bin"; ROOTFS="$ROOT/rootfs/05-rootfs-minimal.ext4"
BROKER="${BROKER:-$HOME/MonkeyITM-VM/target/release/broker}"
P="$ROOT/logs/05-fleet-$MODE"

"$ROOT/scripts/verify-inputs.sh" --installed || { echo "input verification failed" >&2; exit 2; }
"$ROOT/scripts/verify-inputs.sh" broker "$BROKER" || { echo "broker does not match inputs.lock" >&2; exit 2; }
"$ROOT/scripts/verify-inputs.sh" kernel/vmlinux.bin "$KERNEL" || { echo "kernel does not match inputs.lock" >&2; exit 2; }
"$ROOT/scripts/verify-inputs.sh" rootfs/05-rootfs-minimal.ext4 "$ROOTFS" || { echo "rootfs does not match inputs.lock" >&2; exit 2; }

mkdir -p "$ROOT/logs/archive"
for db in "$P.db" "$P-doc.db" "$P-shell.db"; do   # keep earlier evidence
  [[ -e "$db" ]] && mv "$db" "$ROOT/logs/archive/$(basename "${db%.db}")-$(date -u +%Y%m%dT%H%M%SZ).db"
  rm -f "$db-wal" "$db-shm"
done
: > "$P-doc.log"; : > "$P-shell.log"   # keep the serial logs owned by this user

RUN=(python3 -B); JAIL_ARGS=()
if [[ "${JAIL:-0}" == "1" ]]; then RUN=(sudo python3 -B); JAIL_ARGS=(--jailer "$ROOT/bin/jailer")
else echo "WARN: running WITHOUT the jailer (set JAIL=1 to confine each VMM)" >&2; fi
"${RUN[@]}" "$ROOT/scripts/05-fleet.py" --firecracker "$FC" --kernel "$KERNEL" --rootfs "$ROOTFS" \
  --log-prefix "$P" --tripwire "$TRIP" --run-timeout 60 "${JAIL_ARGS[@]}"
RC=$?

fail=0
pass() { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; fail=1; }
[[ "$RC" -eq "$WANT" ]] && pass "fleet exit code $RC" || bad "fleet exit code $RC, wanted $WANT"

OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
for db in "$P.db" "$P-doc.db" "$P-shell.db"; do
  name="$(basename "${db%.db}")"
  python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.execute("PRAGMA journal_mode=DELETE")' "$db"
  if "$BROKER" verify --db "$db" > "$OUT" 2>&1 && grep -q '^OK: every record is in the chain and unchanged$' "$OUT"; then
    pass "$name: broker verify"
  else bad "$name: broker verify"; cat "$OUT"; fi
  if [[ -n "${ANCHOR_KEY_FILE:-}" ]]; then
    if python3 "$ROOT/scripts/anchor.py" write "$db" "$name" >/dev/null && python3 "$ROOT/scripts/anchor.py" verify "$db" "$name" >/dev/null; then
      pass "$name: anchored"
    else bad "$name: anchor"; fi
  elif [[ "${ALLOW_NO_ANCHOR:-0}" != "1" ]]; then bad "ANCHOR_KEY_FILE not set (or ALLOW_NO_ANCHOR=1 for a demo)"; fi
  "$BROKER" export --db "$db" --format text --out "${db%.db}.txt"
done

has()    { grep -qE "$2" "$P-$1.events.log" && pass "$1: $3" || bad "$1: $3"; }
hasnt()  { grep -qE "$2" "$P-$1.events.log" && bad "$1: $3" || pass "$1: $3"; }
has   doc   '^LSM .*landlock'                                "Landlock active"
has   doc   '^ALLOW doc_agent write /tmp/doc/benign\.txt'    "allowed write worked"
has   doc   '^DENY doc_agent write /tmp/payload\.sh errno=13' "write outside its directory denied"
has   shell '^LSM .*landlock'                                "Landlock active"
has   shell '^DENY shell_agent execve /tmp/payload\.sh errno=13' "payload exec denied"
hasnt doc   'shell_agent'                                    "no shell_agent lines in this VM"
hasnt shell 'doc_agent'                                      "no doc_agent lines in this VM"
if [[ "$MODE" == default ]]; then
  has doc   '^DONE supervisor' "finished"
  has shell '^DONE supervisor' "finished"
  grep -q 'TRIPWIRE' "$P.txt" && bad "fleet tripwire fired in a default run" || pass "fleet tripwire stayed quiet"
else
  grep -qE 'TRIPWIRE denials=3' "$P.txt" && pass "fleet tripwire fired at 3 denials across VMs" || bad "fleet tripwire not recorded"
fi
[[ $fail -eq 0 ]] && echo "==> Fleet ($MODE) PASS" || echo "==> Fleet ($MODE) has failures; see above." >&2
exit "$fail"
