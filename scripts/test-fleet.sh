#!/usr/bin/env bash
# Control validation for one-VM-per-agent, in real guests:
#   1. isolation: agents without their sandbox still cannot see or reach each other
#   2. tripwire:  denials summed across VMs stop a VM that is still running
# With JAIL=1 the VMs run under the jailer (needs sudo).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fail=0
JAIL_ARGS=(); RUN=(python3 -B)
if [[ "${JAIL:-0}" == "1" ]]; then RUN=(sudo python3 -B); JAIL_ARGS=(--jailer "$ROOT/bin/jailer"); fi

image() {  # image <name> <shell-agent extra define>; replaces the agents, builds <name>.ext4
  local d="$W/$1"; mkdir "$d"; cp -r "$ROOT/scripts" "$d/scripts"
  printf '#define ME "doc_agent"\n#include "05-fleet-probe.c"\n' > "$d/scripts/05-doc_agent.c"
  printf '#define ME "shell_agent"\n%s\n#include "05-fleet-probe.c"\n' "$2" > "$d/scripts/05-shell_agent.c"
  "$d/scripts/build-minimal-rootfs.sh" "$d/image.ext4" >/dev/null 2>&1 || { echo "FAIL: image build $1"; exit 2; }
}
fleet() {  # fleet <name> <tripwire> <timeout>
  local p="$W/$1/run"
  : > "$p-doc.log"; : > "$p-shell.log"
  "${RUN[@]}" "${FLEET:-$ROOT/scripts/05-fleet.py}" --firecracker "$ROOT/bin/firecracker" \
    --kernel "${KERNEL:-$ROOT/kernel/vmlinux.bin}" --rootfs "$W/$1/image.ext4" \
    --log-prefix "$p" --tripwire "$2" --run-timeout "$3" "${JAIL_ARGS[@]}" 2>&1 | sed 's/^/   /'
  return "${PIPESTATUS[0]}"
}
check() { if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }
events() { python3 -c "import sqlite3,sys;[print(r[0]) for r in sqlite3.connect(sys.argv[1]).execute('select detail from run_events')]" "$1"; }

echo "== isolation"
image iso ''
fleet iso 99 30; rc=$?
check "fleet exited cleanly" "[[ $rc -eq 0 ]]"
for a in doc shell; do
  e="$W/iso/run-$a.events.log"
  n=$(grep -c ' probe ok ' "$e"); bad=$(grep -c 'NOT-ISOLATED' "$e")
  check "$a: all 9 probes held (ok=$n bad=$bad)" "[[ $n -eq 9 && $bad -eq 0 ]]"
  grep -E 'NOT-ISOLATED' "$e" | sed 's/^/   /'
done
check "the VMs kept separate chains" "! grep -q shell_agent '$W/iso/run-doc.events.log' && ! grep -q doc_agent '$W/iso/run-shell.events.log'"

echo "== control: both agents in one guest must fail the isolation probes"
sed -i 's|"/init-doc"|"/init"|; s|"/init-shell"|"/init"|' "$W/iso/scripts/05-fleet.py"
FLEET="$W/iso/scripts/05-fleet.py" fleet iso 99 30 >/dev/null
caught=$(cat "$W"/iso/run-*.events.log | grep -cE 'NOT-ISOLATED peer-(marker|process)')
check "probes detect a shared guest (caught=$caught)" "[[ $caught -ge 1 ]]"
rm -f "$W"/iso/run*.db*

echo "== fleet tripwire"
image trip '#define LINGER 1'
cp -r "$ROOT/scripts/05-doc_agent.c" "$W/trip/scripts/05-doc_agent.c"
"$W/trip/scripts/build-minimal-rootfs.sh" "$W/trip/image.ext4" >/dev/null 2>&1 || { echo "FAIL: image build"; exit 2; }
s=$(date +%s); fleet trip 3 25; rc=$?; took=$(( $(date +%s) - s ))
check "fleet reports it was tripped (rc=$rc)" "[[ $rc -eq 3 ]]"
check "the lingering VM was stopped, not timed out (${took}s)" "[[ $took -lt 15 ]]"
fe="$(events "$W/trip/run.db")"
check "tripwire recorded in the fleet chain" "grep -q '^TRIPWIRE denials=3' <<<\"\$fe\""
check "shell VM recorded as stopped (rc=3)" "grep -q '^VM shell rc=3 chain=OK' <<<\"\$fe\""
check "doc VM chain intact" "grep -q '^VM doc rc=[03] chain=OK' <<<\"\$fe\""

[[ $fail -eq 0 ]] && echo "==> FLEET PASS" || { echo "==> FLEET FAILED"; exit 1; }
