#!/usr/bin/env bash
# Rebuild the three guest binaries from source and install them into the
# SS1 rootfs image. Requires sudo (loop-mount). Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="$ROOT/rootfs/05-rootfs.ext4"
# GEN-15: private paths only. A fixed /tmp path would be followed by the sudo steps below.
WORK="$(mktemp -d)"; MNT="$WORK/mnt"; mkdir "$MNT"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "==> building (musl, static)"
musl-gcc -static -O2 -Wall -Wextra               -o "$WORK/05-supervisor"  "$ROOT/scripts/05-supervisor.c"
musl-gcc -static -O2 -Wall -Wextra -Wno-unused-parameter -o "$WORK/05-doc_agent" "$ROOT/scripts/05-doc_agent.c"
musl-gcc -static -O2 -Wall -Wextra -Wno-unused-parameter -o "$WORK/05-shell_agent" "$ROOT/scripts/05-shell_agent.c"

echo "==> installing into $ROOTFS"
sudo mount -o loop "$ROOTFS" "$MNT"
sudo install -m 0755 "$WORK/05-supervisor"  "$MNT/05-supervisor"
sudo install -m 0755 "$WORK/05-doc_agent"   "$MNT/05-doc_agent"
sudo install -m 0755 "$WORK/05-shell_agent" "$MNT/05-shell_agent"
sudo umount "$MNT"
echo "==> done"
