#!/usr/bin/env bash
set -uo pipefail
MODE="${1:-default}"
case "$MODE" in default|kill) ;; *) echo "usage: $0 [default|kill]" >&2; exit 2;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FC="$ROOT/bin/firecracker"
KERNEL="$ROOT/kernel/vmlinux.bin"
ROOTFS="$ROOT/rootfs/05-rootfs.ext4"
SERIAL="$ROOT/logs/05-attack-${MODE}.log"
SERIAL_NORM="$ROOT/logs/05-attack-${MODE}.norm.log"
EVENTS="$ROOT/logs/05-attack-${MODE}.events.log"
RECEIPT="$ROOT/logs/05-attack-${MODE}.db"
EXPORT_JSON="$ROOT/logs/05-attack-${MODE}.json"
EXPORT_TXT="$ROOT/logs/05-attack-${MODE}.txt"
BROKER="${BROKER:-$HOME/MonkeyITM-VM/target/release/broker}"

for f in "$FC" "$KERNEL" "$ROOTFS" \
         "$ROOT/scripts/05-supervisor.py" "$ROOT/scripts/05-receipt.py" \
         "$BROKER"; do
  [[ -e "$f" ]] || { echo "missing: $f" >&2; exit 2; }
done
rm -f "$RECEIPT" "$RECEIPT-wal" "$RECEIPT-shm"

INIT_TARGET=/init
[[ "$MODE" == "kill" ]] && INIT_TARGET=/init-trip

echo "==> Starting 05 supervisor ($MODE run, init=$INIT_TARGET, timeout 60s)"
python3 "$ROOT/scripts/05-supervisor.py" \
  --firecracker "$FC" --kernel "$KERNEL" --rootfs "$ROOTFS" \
  --serial-log "$SERIAL" --events-log "$EVENTS" --receipt-db "$RECEIPT" \
  --init-target "$INIT_TARGET" --run-timeout 60
echo

echo "==> Normalizing serial log"
sed -E 's/\r$//; s/^(# ?)+//' "$SERIAL" > "$SERIAL_NORM"

echo "==> Verifying receipt chain with broker"
python3 - "$RECEIPT" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
c.execute("PRAGMA journal_mode=DELETE")
c.close()
PY
rm -f "$RECEIPT-wal" "$RECEIPT-shm"

fail=0
pass() { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; fail=1; }

if "$BROKER" verify --db "$RECEIPT" > /tmp/broker-verify-05.out 2>&1 \
   && grep -q '^OK: every record is in the chain and unchanged$' /tmp/broker-verify-05.out; then
  pass "broker verify: every record is in the chain and unchanged"
else
  bad "broker verify failed"; cat /tmp/broker-verify-05.out
fi

"$BROKER" export --db "$RECEIPT" --format json --out "$EXPORT_JSON"
"$BROKER" export --db "$RECEIPT" --format text --out "$EXPORT_TXT"

assert_has() {
  local pat="$1" label="$2"
  if grep -qE "$pat" "$EXPORT_TXT"; then pass "$label"; else bad "$label"; fi
}

assert_has 'RUN VSOCK.*\bLSM\b'                                       "LSM line present"
assert_has 'RUN VSOCK.*\blandlock\b'                                  "LSM stack contains landlock"
assert_has 'RUN VSOCK.*HELLO supervisor'                              "HELLO supervisor"
assert_has 'RUN VSOCK.*HELLO doc_agent'                               "HELLO doc_agent"
assert_has 'RUN VSOCK.*ALLOW doc_agent write /tmp/doc/benign\.txt'    "ALLOW doc_agent write benign.txt"
assert_has 'RUN VSOCK.*DENY doc_agent write /tmp/payload\.sh errno=13' "DENY doc_agent write errno=13"
assert_has 'RUN VSOCK.*DENY doc_agent execve /tmp/payload\.sh'        "DENY doc_agent execve (SIGSYS)"
assert_has 'RUN VSOCK.*HELLO shell_agent'                             "HELLO shell_agent"
assert_has 'RUN VSOCK.*TRY shell_agent execve /tmp/payload\.sh'       "TRY shell_agent execve"
assert_has 'RUN VSOCK.*DENY shell_agent execve /tmp/payload\.sh errno=13' "DENY shell_agent execve errno=13"

# Guardrail (§10): reject EROFS masquerading as a Landlock denial.
if grep -qE 'RUN VSOCK.*DENY.*errno=30' "$EXPORT_TXT"; then
  bad "found errno=30 (EROFS) — tmpfs mount failed; denial is vacuous"
else
  pass "no errno=30 (EROFS) denials"
fi

if [[ "$MODE" == "default" ]]; then
  assert_has 'RUN VSOCK.*DONE supervisor'                             "DONE supervisor"
  if grep -qE 'RUN VSOCK.*TRIPWIRE' "$EXPORT_TXT"; then
    bad "TRIPWIRE fired in default run (threshold 4, should not)"
  else
    pass "no TRIPWIRE in default run"
  fi
else
  assert_has 'RUN VSOCK.*TRIPWIRE denials>=3'                         "TRIPWIRE fired at 3 denials"
  assert_has 'RUN VSOCK.*HALT supervisor'                             "HALT supervisor"
  if grep -qE 'RUN VSOCK.*DONE supervisor' "$EXPORT_TXT"; then
    bad "DONE supervisor present in kill run (should not be)"
  else
    pass "no DONE supervisor in kill run"
  fi
fi

echo
echo "==> vsock lines, in order:"
sed 's/^/   /' "$EVENTS"
echo
if [[ "$fail" -eq 0 ]]; then
  echo "==> Phase 5 SS1 ($MODE) PASS"
else
  echo "==> Phase 5 SS1 ($MODE) has failures; see above." >&2
fi
echo
echo "==> Receipt json: $EXPORT_JSON"
echo "==> Receipt text: $EXPORT_TXT"
echo "==> Serial log:   $SERIAL_NORM"
echo "==> Events log:   $EVENTS"
exit "$fail"
