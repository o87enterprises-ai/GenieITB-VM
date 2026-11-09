#!/usr/bin/env bash
# EXT-06: build the guest rootfs from static binaries only: no distro, shell, or SSH.
# Needs musl-gcc, fakeroot, mke2fs. No root and no loop mount.
#   usage: build-minimal-rootfs.sh [out.ext4]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/rootfs/05-rootfs-minimal.ext4}"
S="$ROOT/scripts"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
T="$WORK/tree"
CC=(musl-gcc -static -O2 -Wall -Wextra -Wno-unused-parameter -s)

# Landlock rulesets open these directories, and the kernel needs the mount points.
mkdir -p "$T"/{bin,dev,lib,lib64,proc,securityfs,sys,tmp,usr/bin,usr/lib,usr/local/lib}
chmod 1777 "$T/tmp"

"${CC[@]}" -o "$T/05-supervisor"  "$S/05-supervisor.c"
"${CC[@]}" -o "$T/05-doc_agent"   "$S/05-doc_agent.c"
"${CC[@]}" -o "$T/05-shell_agent" "$S/05-shell_agent.c"
"${CC[@]}" '-DTRIPWIRE="4"' -o "$T/init"      "$S/05-init.c"
"${CC[@]}" '-DTRIPWIRE="3"' -o "$T/init-trip" "$S/05-init.c"
# shell_agent's allowed-exec control target.
echo 'int main(void){return 0;}' > "$WORK/true.c"
"${CC[@]}" -o "$T/bin/true" "$WORK/true.c"
chmod 0755 "$T"/05-* "$T"/init "$T"/init-trip "$T"/bin/true

rm -f "$OUT"
fakeroot -- bash -c "chown -R 0:0 '$T' && mke2fs -q -t ext4 -m 0 -L genie-min -d '$T' '$OUT' 16M"
e2fsck -fn "$OUT" >/dev/null
sha256sum "$OUT"
if [[ "$OUT" == "$ROOT/rootfs/05-rootfs-minimal.ext4" ]]; then
  # The image is not byte-reproducible, so pin each build. Detects a later swap.
  H="$(sha256sum "$OUT" | cut -d' ' -f1)"
  grep -v '  rootfs/05-rootfs-minimal.ext4  -$' "$ROOT/inputs.lock" > "$WORK/lock"
  echo "$H  rootfs/05-rootfs-minimal.ext4  -" >> "$WORK/lock"
  cat "$WORK/lock" > "$ROOT/inputs.lock"
fi
