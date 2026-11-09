#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
gcc -O1 -w -I"$HERE" -o "$W/lineclass" "$HERE/05-lineclass-test.c" && "$W/lineclass" || exit 1
python3 -B "$HERE/test-records.py"
