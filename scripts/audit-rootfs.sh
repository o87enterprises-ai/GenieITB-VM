#!/usr/bin/env bash
# EXT-06: read-only audit of a guest rootfs image (uses debugfs; no mount, no root).
# Fails if it contains credentials/SSH material or services this workload does not need.
#   usage: audit-rootfs.sh <rootfs.ext4>
set -uo pipefail
IMG="${1:?usage: $0 <rootfs.ext4>}"
DBG="$(command -v debugfs || echo /sbin/debugfs)"
fail=0
d() { "$DBG" -R "$1" "$IMG" 2>/dev/null; }
bad() { echo "FOUND: $*"; fail=1; }

# SSH host keys and authorized_keys (the stock bionic image ships both; they are public).
d 'ls /etc/ssh' | tr -s ' ' '\n' | grep -E '^ssh_host_.*_key$' | while read -r k; do echo "FOUND: /etc/ssh/$k"; done | grep -q . && { bad "SSH host private keys under /etc/ssh"; }
d 'ls /root/.ssh' | tr -s ' ' '\n' | grep -qx authorized_keys && bad "/root/.ssh/authorized_keys"
d 'stat /usr/sbin/sshd' | grep -q 'Inode:' && bad "sshd binary present"

# Accounts with a usable password hash.
d 'cat /etc/shadow' | awk -F: '$2 !~ /^[*!]/ && $2 != "" {print $1}' | grep -q . && bad "account(s) with a password hash in /etc/shadow"

# Anything that would start network services at boot.
for p in /etc/init.d/ssh /etc/systemd/system/multi-user.target.wants; do
  d "stat $p" | grep -q 'Inode:' && echo "note: $p exists (check what it starts)"
done

# Release age.
rel="$(for f in /etc/os-release /usr/lib/os-release /etc/lsb-release; do d "cat $f"; done | sed -n -e 's/^PRETTY_NAME=//p' -e 's/^DISTRIB_DESCRIPTION=//p' | head -1)"
echo "os-release: ${rel:-unknown}"
case "$rel" in
  *18.04*|*16.04*|*14.04*)
    if [[ "${ALLOW_EOL:-0}" == "1" ]]; then echo "WARN: end-of-life distribution: $rel (ALLOW_EOL=1)"
    else bad "end-of-life distribution: $rel"; fi ;;
esac

[[ $fail -eq 0 ]] && echo "rootfs audit: PASS" || { echo "rootfs audit: FAIL"; exit 1; }
