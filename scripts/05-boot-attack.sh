#!/usr/bin/env bash
set -uo pipefail
MODE="${1:-default}"
case "$MODE" in default|kill) ;; *) echo "usage: $0 [default|kill]" >&2; exit 2;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FC="$ROOT/bin/firecracker"
KERNEL="${KERNEL:-$ROOT/kernel/vmlinux.bin}"
ROOTFS="${ROOTFS:-$ROOT/rootfs/05-rootfs-minimal.ext4}"   # build: scripts/build-minimal-rootfs.sh
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

# EXT-05: refuse to run with unpinned/modified VMM binaries.
"$ROOT/scripts/verify-inputs.sh" --installed || { echo "input verification failed" >&2; exit 2; }
"$ROOT/scripts/verify-inputs.sh" broker "$BROKER" || { echo "broker does not match inputs.lock" >&2; exit 2; }
[[ -n "${JAIL_USER:-}" ]] || echo "WARN: running WITHOUT the jailer (set JAIL_USER=<account> to confine the VMM)" >&2

# EXT-04: archive the previous receipt instead of destroying evidence.
if [[ -e "$RECEIPT" ]]; then
  mkdir -p "$ROOT/logs/archive"
  mv "$RECEIPT" "$ROOT/logs/archive/05-attack-${MODE}-$(date -u +%Y%m%dT%H%M%SZ).db"
fi
rm -f "$RECEIPT-wal" "$RECEIPT-shm"

INIT_TARGET=/init
[[ "$MODE" == "kill" ]] && INIT_TARGET=/init-trip

echo "==> Starting 05 supervisor ($MODE run, init=$INIT_TARGET, timeout 60s)"
# EXT-03: JAIL_USER=<dedicated account> runs the VMM under the jailer. Only the supervisor
# is started with sudo, and it drops to this user for everything that handles guest data.
SUPERVISOR=(python3)
JAIL_ARGS=()
if [[ -n "${JAIL_USER:-}" ]]; then
  JAIL_UID="$(id -u "$JAIL_USER")" || { echo "no such user: $JAIL_USER" >&2; exit 2; }
  JAIL_GID="$(id -g "$JAIL_USER")"
  [[ "$JAIL_UID" -ne 0 ]] || { echo "JAIL_USER must not be root" >&2; exit 2; }
  SUPERVISOR=(sudo python3 -B)
  JAIL_ARGS=(--jailer "$ROOT/bin/jailer" --jail-uid "$JAIL_UID" --jail-gid "$JAIL_GID")
  : > "$SERIAL"; : > "$EVENTS"   # keep the logs owned by this user, not root
fi
"${SUPERVISOR[@]}" "$ROOT/scripts/05-supervisor.py" \
  --firecracker "$FC" --kernel "$KERNEL" --rootfs "$ROOTFS" \
  --serial-log "$SERIAL" --events-log "$EVENTS" --receipt-db "$RECEIPT" \
  --init-target "$INIT_TARGET" --run-timeout 60 "${JAIL_ARGS[@]}"
SUPERVISOR_RC=$?
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

if [[ "$SUPERVISOR_RC" -eq 0 ]]; then
  pass "VMM exited cleanly"
else
  bad "supervisor exited $SUPERVISOR_RC (VMM timeout or failure)"
fi

if "$BROKER" verify --db "$RECEIPT" > /tmp/broker-verify-05.out 2>&1 \
   && grep -q '^OK: every record is in the chain and unchanged$' /tmp/broker-verify-05.out; then
  pass "broker verify: every record is in the chain and unchanged"
else
  bad "broker verify failed"; cat /tmp/broker-verify-05.out
fi

# EXT-04: keyed out-of-band anchor. Strict by default; ALLOW_NO_ANCHOR=1 to opt out (demo only).
if [[ -n "${ANCHOR_KEY_FILE:-}" ]]; then
  if python3 "$ROOT/scripts/anchor.py" write "$RECEIPT" "05-${MODE}" \
     && python3 "$ROOT/scripts/anchor.py" verify "$RECEIPT" "05-${MODE}"; then
    pass "receipt anchored and anchor-verified"
  else
    bad "receipt anchoring failed"
  fi
elif [[ "${ALLOW_NO_ANCHOR:-0}" == "1" ]]; then
  echo "WARN: no ANCHOR_KEY_FILE; receipt is NOT tamper-evident against a host-level attacker" >&2
else
  bad "ANCHOR_KEY_FILE not set (set it, or ALLOW_NO_ANCHOR=1 for a demo run)"
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
