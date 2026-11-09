#!/usr/bin/env bash
# Control validation (project rule P6): boots a throwaway image where doc_agent is replaced by
# 05-sandbox-probe.c and asserts every forbidden operation is refused inside a real guest.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp -r "$ROOT/scripts" "$W/scripts"
cp "$W/scripts/05-sandbox-probe.c" "$W/scripts/05-doc_agent.c"
"$W/scripts/build-minimal-rootfs.sh" "$W/probe.ext4" >/dev/null 2>&1 || { echo "FAIL: image build"; exit 2; }
python3 -B "$ROOT/scripts/05-supervisor.py" --firecracker "$ROOT/bin/firecracker" \
  --kernel "${KERNEL:-$ROOT/kernel/vmlinux.bin}" --rootfs "$W/probe.ext4" \
  --serial-log "$W/serial" --events-log "$W/events" --receipt-db "$W/r.db" \
  --init-target /init --run-timeout 30 2>/dev/null
grep -E 'probe (ok|NOT-DENIED)|BADLINE|ENFORCED' "$W/events" | sed -E 's/^(TRY|ERROR) doc_agent //'
ok=$(grep -c 'probe ok' "$W/events"); bad=$(grep -c 'NOT-DENIED' "$W/events")
echo "probes passed=$ok failed=$bad"
badlines=$(grep -c '^BADLINE from doc_agent$' "$W/events")
forged=$(grep -cE '^HALT supervisor$|/etc/shadow' "$W/events")
echo "forged lines rejected=$badlines recorded=$forged"
if [[ "$ok" -eq 12 && "$bad" -eq 0 && "$badlines" -eq 2 && "$forged" -eq 0 ]]; then
  echo "==> SANDBOX PROBE PASS"
else
  echo "==> SANDBOX PROBE FAILED"; exit 1
fi
