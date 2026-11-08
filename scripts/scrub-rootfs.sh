#!/usr/bin/env bash
# EXT-06 interim: write a scrubbed COPY of a rootfs with SSH material removed. Uses
# debugfs -w on a file you own (no root, no mount). This does NOT fix end-of-life
# userland; replace the image with a minimal static one (see SECURITY_REVIEW.md EXT-06).
#   usage: scrub-rootfs.sh <in.ext4> <out.ext4>
set -euo pipefail
IN="${1:?in}"; OUT="${2:?out}"; DBG="$(command -v debugfs || echo /sbin/debugfs)"
[[ "$IN" != "$OUT" ]] || { echo "refusing to modify in place" >&2; exit 2; }
cp --reflink=auto "$IN" "$OUT"
for f in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_ecdsa_key \
         /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub \
         /root/.ssh/authorized_keys /usr/sbin/sshd /etc/init.d/ssh; do
  "$DBG" -w -R "rm $f" "$OUT" >/dev/null 2>&1 || true
done
e2fsck -fn "$OUT" >/dev/null 2>&1 || echo "WARN: e2fsck reports issues; check the image" >&2
echo "wrote $OUT"
