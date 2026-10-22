#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERIAL="$ROOT/logs/03-boot-vsock.log"
EVENTS="$ROOT/logs/03-vsock-events.log"
NORM="$ROOT/logs/03-boot-vsock.norm.log"
ROOTFS="$ROOT/rootfs/rootfs-vsock.ext4"
RUN_TIMEOUT="${RUN_TIMEOUT:-15}"

say() { printf '\n==> %s\n' "$*"; }

for f in "$ROOT/bin/firecracker" "$ROOT/kernel/vmlinux.bin" "$ROOTFS" \
         "$ROOT/scripts/03-supervisor.py"; do
  [ -f "$f" ] || { echo "ERROR: missing $f — run 03-setup.sh first"; exit 1; }
done

chmod +x "$ROOT/scripts/03-supervisor.py"

say "Starting supervisor (API + vsock, timeout ${RUN_TIMEOUT}s)"
python3 "$ROOT/scripts/03-supervisor.py" \
  --firecracker "$ROOT/bin/firecracker" \
  --kernel      "$ROOT/kernel/vmlinux.bin" \
  --rootfs      "$ROOTFS" \
  --serial-log  "$SERIAL" \
  --events-log  "$EVENTS" \
  --run-timeout "$RUN_TIMEOUT"

say "Normalizing serial log"
sed -E 's/\r$//; s/^(# ?)+//' "$SERIAL" > "$NORM"

say "Assertions"

if ! grep -qx '===END===' "$NORM"; then
  echo "FAIL: shell never reached end marker"
  tail -20 "$NORM"
  exit 1
fi
echo "PASS: guest booted and ran shell commands"

if grep -q 'link/ether' "$NORM"; then
  echo "FAIL: ethernet interface present in guest"
  exit 1
fi
if ! grep -q 'link/loopback' "$NORM"; then
  echo "FAIL: loopback interface not found"
  exit 1
fi
echo "PASS: only loopback interface (no NIC)"

if grep -qE '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+' "$NORM"; then
  echo "FAIL: TCP sockets present in guest"
  exit 1
fi
echo "PASS: no TCP sockets"

if awk '/^===TCP6===/{f=1;next} /^===END===/{f=0} f' "$NORM" \
     | grep -qE '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+'; then
  echo "FAIL: TCP6 sockets present in guest"
  exit 1
fi
echo "PASS: no TCP6 sockets"

if ! grep -qx '===VSOCK_DONE===' "$NORM"; then
  echo "FAIL: guest never reached VSOCK_DONE"
  echo "--- last 25 lines of normalized serial ---"
  tail -25 "$NORM"
  echo "--- events log (cat -v) ---"
  cat -v "$EVENTS" || true
  exit 1
fi
echo "PASS: guest reached VSOCK_DONE"

if ! grep -q 'hello from guest' "$EVENTS"; then
  echo "FAIL: supervisor did not receive the vsock payload"
  echo "--- events log (cat -v) ---"
  cat -v "$EVENTS" || true
  echo "--- last 25 lines of normalized serial ---"
  tail -25 "$NORM"
  exit 1
fi
echo "PASS: supervisor received 'hello from guest' over vsock"

say "Phase 3 complete — guest <-> host control plane established over vsock."
say "Serial log: $SERIAL"
say "Events log: $EVENTS"
