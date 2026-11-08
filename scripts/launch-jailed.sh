#!/usr/bin/env bash
# EXT-03: run Firecracker under the jailer (dedicated uid/gid, chroot, pid namespace,
# cgroup v2 limits). UNTESTED in this repo's CI: it needs root and a dedicated account,
# neither of which the build host used for review had. A reviewer with root must run it.
#
# What this script does NOT yet do: scripts/05-supervisor.py still launches firecracker
# directly and listens for vsock at a tmpdir path. To use the jail, the supervisor must
# (a) take --api-sock and the vsock uds path as paths *inside* the chroot, and (b) bind
# its listener at <chroot>/root/<uds_path>_5000. That change is mechanical but untestable
# without root, so it is left for the reviewer rather than shipped blind.
#
#   sudo ./scripts/launch-jailed.sh <vm-id> <uid> <gid> <kernel> <rootfs>
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root (jailer requirement)" >&2; exit 2; }
ID="${1:?vm id}"; UID_="${2:?uid}"; GID_="${3:?gid}"; KERNEL="${4:?kernel}"; ROOTFS="${5:?rootfs}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$UID_" -ne 0 && "$GID_" -ne 0 ]] || { echo "uid/gid must not be root" >&2; exit 2; }
[[ "$ID" =~ ^[A-Za-z0-9-]{1,64}$ ]] || { echo "bad vm id" >&2; exit 2; }

"$ROOT/scripts/verify-inputs.sh" --installed

BASE="${CHROOT_BASE:-/srv/jailer}"
# CVE-2026-1386: the base must not be writable by untrusted users, and must be a real directory.
install -d -m 0755 -o root -g root "$BASE"
[[ ! -L "$BASE" ]] || { echo "$BASE is a symlink" >&2; exit 2; }
JROOT="$BASE/firecracker/$ID/root"
[[ ! -e "$BASE/firecracker/$ID" ]] || { echo "jail $ID already exists; remove it first" >&2; exit 2; }
install -d -m 0750 -o "$UID_" -g "$GID_" "$JROOT"
# Copy (not link) boot artifacts into the jail; rootfs is attached read-only by the VMM config.
install -m 0440 -o "$UID_" -g "$GID_" "$KERNEL" "$JROOT/vmlinux.bin"
install -m 0440 -o "$UID_" -g "$GID_" "$ROOTFS" "$JROOT/rootfs.ext4"

exec "$ROOT/bin/jailer" \
  --id "$ID" --exec-file "$ROOT/bin/firecracker" \
  --uid "$UID_" --gid "$GID_" \
  --chroot-base-dir "$BASE" --cgroup-version 2 --new-pid-ns \
  --cgroup memory.max=$((384*1024*1024)) --cgroup cpu.max="100000 100000" --cgroup pids.max=64 \
  -- --api-sock /run/firecracker.socket
