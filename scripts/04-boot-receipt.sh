#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FC="$ROOT/bin/firecracker"
KERNEL="$ROOT/kernel/vmlinux.bin"
ROOTFS="$ROOT/rootfs/rootfs-vsock.ext4"
SERIAL="$ROOT/logs/04-boot-receipt.log"
SERIAL_NORM="$ROOT/logs/04-boot-receipt.norm.log"
EVENTS="$ROOT/logs/04-vsock-events.log"
RECEIPT="$ROOT/logs/04-receipt.db"
BROKER="${BROKER:-$HOME/MonkeyITM-VM/target/release/broker}"

for f in "$FC" "$KERNEL" "$ROOTFS" "$ROOT/scripts/04-supervisor.py" "$ROOT/scripts/04-receipt.py" "$BROKER"; do
  [[ -e "$f" ]] || { echo "missing: $f" >&2; exit 2; }
done
rm -f "$RECEIPT" "$RECEIPT-wal" "$RECEIPT-shm"

echo "==> Starting supervisor (API + vsock + receipt, timeout 15s)"
python3 "$ROOT/scripts/04-supervisor.py" \
  --firecracker "$FC" --kernel "$KERNEL" --rootfs "$ROOTFS" \
  --serial-log "$SERIAL" --events-log "$EVENTS" --receipt-db "$RECEIPT" \
  --run-timeout 15
echo

echo "==> Normalizing serial log"
sed -E 's/\r$//; s/^(# ?)+//' "$SERIAL" > "$SERIAL_NORM"

echo "==> Assertions"
fail=0
pass() { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; fail=1; }

grep -qx '===END===' "$SERIAL_NORM" \
  && pass "guest booted and ran shell commands" \
  || bad "guest did not reach ===END==="

if grep -q 'link/ether' "$SERIAL_NORM"; then
  bad "found a NIC (link/ether)"
else
  pass "only loopback interface (no NIC)"
fi

grep -q 'link/loopback' "$SERIAL_NORM" \
  && pass "loopback interface present" \
  || bad "no loopback interface"

tcp_rows=$(awk '/^===TCP===$/{f=1;next} /^===TCP6===$/{f=0} f' "$SERIAL_NORM" \
  | grep -Ec '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+' || true)
tcp_rows=${tcp_rows:-0}
if [[ "$tcp_rows" -eq 0 ]]; then pass "no TCP sockets"
else bad "found $tcp_rows TCP socket row(s)"; fi

tcp6_rows=$(awk '/^===TCP6===$/{f=1;next} /^===VSOCK===$/{f=0} f' "$SERIAL_NORM" \
  | grep -Ec '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+' || true)
tcp6_rows=${tcp6_rows:-0}
if [[ "$tcp6_rows" -eq 0 ]]; then pass "no TCP6 sockets"
else bad "found $tcp6_rows TCP6 socket row(s)"; fi

grep -qx '===VSOCK_DONE===' "$SERIAL_NORM" \
  && pass "guest reached VSOCK_DONE" \
  || bad "guest never reached VSOCK_DONE"

grep -q 'hello from guest' "$EVENTS" \
  && pass "supervisor received 'hello from guest' over vsock" \
  || bad "supervisor did not receive hello from guest"

echo
echo "==> Verifying receipt chain with broker"
python3 - "$RECEIPT" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
c.execute("PRAGMA journal_mode=DELETE")
c.close()
PY
rm -f "$RECEIPT-wal" "$RECEIPT-shm"
if "$BROKER" verify --db "$RECEIPT" > /tmp/broker-verify.out 2>&1 \
   && grep -q '^OK: every record is in the chain and unchanged$' /tmp/broker-verify.out; then
  pass "broker verify: every record is in the chain and unchanged"
else
  bad "broker verify failed"
  cat /tmp/broker-verify.out
fi

echo
echo "==> Exporting receipt"
"$BROKER" export --db "$RECEIPT" --format json --out "$ROOT/logs/04-receipt.json"
"$BROKER" export --db "$RECEIPT" --format text --out "$ROOT/logs/04-receipt.txt"

echo
if [[ "$fail" -eq 0 ]]; then
  echo "==> Phase 4 complete — hash-chained receipt written before ack, verified by broker."
else
  echo "==> Phase 4 has failures; see above." >&2
fi
echo
echo "==> Serial log:   $SERIAL"
echo "==> Events log:   $EVENTS"
echo "==> Receipt db:   $RECEIPT"
echo "==> Receipt json: $ROOT/logs/04-receipt.json"
echo "==> Receipt text: $ROOT/logs/04-receipt.txt"
exit "$fail"
