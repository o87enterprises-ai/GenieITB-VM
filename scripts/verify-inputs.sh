#!/usr/bin/env bash
# Fail closed if any pinned input does not match inputs.lock.
#   verify-inputs.sh --installed        check bin/ binaries against the lock
#   verify-inputs.sh <name> <file>      check one downloaded file by lock name
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/inputs.lock"

want() { awk -v n="$1" '$1 !~ /^#/ && $2 == n {print $1; exit}' "$LOCK"; }
check() {
  local name="$1" file="$2" w g
  w="$(want "$name")"
  [[ -n "$w" ]] || { echo "inputs.lock has no entry for $name" >&2; exit 1; }
  [[ "$w" != "TODO" ]] || { echo "inputs.lock entry for $name is still TODO" >&2; exit 1; }
  g="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$g" == "$w" ]] || { echo "HASH MISMATCH $name: want $w got $g" >&2; exit 1; }
  echo "ok  $name"
}

if [[ "${1:-}" == "--installed" ]]; then
  check bin/firecracker "$ROOT/bin/firecracker"
  check bin/jailer      "$ROOT/bin/jailer"
else
  [[ $# -eq 2 ]] || { echo "usage: $0 --installed | <name> <file>" >&2; exit 2; }
  check "$1" "$2"
fi
