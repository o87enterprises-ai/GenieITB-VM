#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT/config/fc-reference.json"
LOG="$ROOT/logs/01-boot-reference.log"
NORM="$ROOT/logs/01-boot-reference.norm.log"
RUN_TIMEOUT="${RUN_TIMEOUT:-15}"

say() { printf '\n==> %s\n' "$*"; }

# --- sanity ---------------------------------------------------------------
for f in "$ROOT/bin/firecracker" "$ROOT/kernel/vmlinux.bin" "$ROOT/rootfs/rootfs.ext4"; do
  [ -f "$f" ] || { echo "ERROR: missing $f — run 00-install-host.sh first"; exit 1; }
done

mkdir -p "$ROOT/config" "$ROOT/logs"

# --- JSON config: deliberately NO "network-interfaces" key ----------------
# No NIC is declared, so Firecracker has nothing to attach. The guest
# therefore cannot enumerate an ethernet interface. Read-only rootfs means
# the guest cannot persist. No PCI means no bus to scan.
cat > "$CONFIG" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$ROOT/kernel/vmlinux.bin",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/bin/sh"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "$ROOT/rootfs/rootfs.ext4",
      "is_root_device": true,
      "is_read_only": true
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 256,
    "smt": false
  }
}
EOF

say "Config written to $CONFIG"
say "Starting Firecracker (timeout ${RUN_TIMEOUT}s)"

# --- Run the VM ----------------------------------------------------------
# set +e is required here: Firecracker exits non-zero when the guest halts
# before the VMM itself issued shutdown ("Detached the serial input due to
# peer close/error"). That is an expected guest-driven exit, not a failure,
# but set -e + pipefail would abort the script before the assertions run.
# We capture the pipeline status explicitly and re-enable set -e after.
set +e
(
  sleep 3
  echo 'export PATH=/sbin:/usr/sbin:/bin:/usr/bin'
  echo 'mount -t proc proc /proc 2>/dev/null || true'
  echo 'mount -t sysfs sysfs /sys 2>/dev/null || true'
  echo 'echo ===IP_LINK==='
  echo 'ip -o link show'
  echo 'echo ===TCP==='
  echo 'cat /proc/net/tcp 2>/dev/null || true'
  echo 'echo ===TCP6==='
  echo 'cat /proc/net/tcp6 2>/dev/null || true'
  echo 'echo ===END==='
  sleep 1
  echo 'poweroff -f'
  sleep 2
) | timeout "$RUN_TIMEOUT" "$ROOT/bin/firecracker" --no-api --config-file "$CONFIG" 2>&1 | tee "$LOG"
FC_RC="${PIPESTATUS[1]:-unknown}"
set -e

say "Firecracker pipeline exit (PIPESTATUS[1]=$FC_RC; 0=clean, 124=timeout, other=firecracker's own code)"

# --- Normalize serial log ------------------------------------------------
# Two normalizations:
#   1. Strip the shell prompt "# " prefixes that init=/bin/sh writes before
#      every echoed command and every line of output (sometimes stacked).
#   2. Strip the trailing \r that Firecracker's serial console appends to
#      every line. Without this, `grep -x` fails: the line is
#      "===END===\r\n", and the pattern "===END===" does not match.
say "Normalizing serial log (stripping prompt prefixes and CR)"
sed -E 's/\r$//; s/^(# ?)+//' "$LOG" > "$NORM"

# --- Assertions ----------------------------------------------------------
say "Assertions"

if ! grep -qx '===END===' "$NORM"; then
  echo "FAIL: shell never reached end marker"
  echo "      --- last 10 lines of normalized log ---"
  tail -10 "$NORM"
  echo "      ---------------------------------------"
  echo "      See $LOG"
  exit 1
fi
echo "PASS: guest booted and ran shell commands"

# Ethernet: a real NIC shows 'link/ether'. Only 'lo' shows 'link/loopback'.
if grep -q 'link/ether' "$NORM"; then
  echo "FAIL: ethernet interface present in guest"
  grep -n 'link/ether' "$NORM"
  exit 1
fi
if ! grep -q 'link/loopback' "$NORM"; then
  echo "FAIL: loopback interface not found — did 'ip link' run?"
  exit 1
fi
echo "PASS: only loopback interface (no NIC)"

# TCP: /proc/net/tcp data rows have the form '   N: HEX:HEX HEX:HEX ...'
# The header line '  sl  local_address ...' does not match this pattern.
if grep -qE '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+' "$NORM"; then
  echo "FAIL: TCP sockets present in guest"
  grep -nE '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+' "$NORM"
  exit 1
fi
echo "PASS: no TCP sockets"

# TCP6: same shape, scoped to the ===TCP6=== ... ===END=== section.
if awk '/^===TCP6===/{f=1;next} /^===END===/{f=0} f' "$NORM" \
     | grep -qE '^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]+:[0-9A-F]+'; then
  echo "FAIL: TCP6 sockets present in guest"
  exit 1
fi
echo "PASS: no TCP6 sockets"

say "Phase 1 complete — guest has zero egress."
say "Raw log:    $LOG"
say "Normalized: $NORM"
