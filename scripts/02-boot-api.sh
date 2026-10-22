#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$ROOT/logs/02-boot-api.log"
NORM="$ROOT/logs/02-boot-api.norm.log"
RUN_TIMEOUT="${RUN_TIMEOUT:-15}"

say() { printf '\n==> %s\n' "$*"; }

for f in "$ROOT/bin/firecracker" "$ROOT/kernel/vmlinux.bin" "$ROOT/rootfs/rootfs.ext4" "$ROOT/scripts/02-supervisor.py"; do
  [ -f "$f" ] || { echo "ERROR: missing $f"; exit 1; }
done

chmod +x "$ROOT/scripts/02-supervisor.py"

say "Starting supervisor (API mode, timeout ${RUN_TIMEOUT}s)"
python3 "$ROOT/scripts/02-supervisor.py" \
  --firecracker "$ROOT/bin/firecracker" \
  --kernel      "$ROOT/kernel/vmlinux.bin" \
  --rootfs      "$ROOT/rootfs/rootfs.ext4" \
  --log         "$LOG" \
  --run-timeout "$RUN_TIMEOUT"

say "Normalizing serial log"
sed -E 's/\r$//; s/^(# ?)+//' "$LOG" > "$NORM"

say "Assertions"

if ! grep -qx '===END===' "$NORM"; then
  echo "FAIL: shell never reached end marker"
  tail -10 "$NORM"
  exit 1
fi
echo "PASS: guest booted and ran shell commands"

if grep -q 'link/ether' "$NORM"; then
  echo "FAIL: ethernet interface present in guest"
  grep -n 'link/ether' "$NORM"
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

say "Phase 2 complete — control plane established, Phase 1 assertions still hold."
say "Log: $LOG"
