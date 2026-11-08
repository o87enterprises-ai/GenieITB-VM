# Hardening status (branch `hardening/ext-review`, base `d04e988`)

Date: 2026-11-08. Host: WSL2 x86_64, **no root**. Nothing here has been independently pentested.

| ID | State | Evidence | Not done / caveat |
|---|---|---|---|
| EXT-02 Firecracker | **Done** | v1.17.0, tarball SHA-256 matches upstream `.sha256.txt`; SS1 default+kill PASS | Re-check advisories GHSA-36j2-f825-qvgc, GHSA-776c-mpj7-jm3r on GitHub (ranges came from secondary trackers) |
| EXT-05 Supply chain | **Partial** | `inputs.lock` + `scripts/verify-inputs.sh` gate FC/jailer; run script refuses on mismatch (negative test passed); `curl\|sh` removed | Kernel tarball, kernel config, reference kernel/rootfs entries are `TODO` and make those paths fail closed; kernel PGP check not added; committed `guest-agent/agent` and `broker` binary unpinned |
| EXT-04 Receipt anchor | **Done in code** | `scripts/anchor.py`: truncation, same-length forge, tampered anchor log, loose key perms all rejected (plain `verify` accepted the forge); SS1 run script requires it by default; old receipts archived not deleted | Protection exists only if key + anchor log sit behind a different privilege boundary than the receipt writer. Use `ANCHOR_PUSH_CMD` to a remote append-only store |
| EXT-01 NIC guard | **Done (guard only)** | Supervisor aborts on any NIC/MMDS in `/vm/config` before `InstanceStart`; unit-tested with stubbed configs | Not tested against a real NIC (needs tap/root). **No perimeter exists**; do not attach a NIC |
| EXT-07 Guest kernel | **Done** | `scripts/audit-kernel-config.sh` PASS; built `kernel/vmlinux-hardened.bin`; boot log shows `capability,landlock,lockdown,yama`; SS1 default+kill PASS | Kernel not yet promoted to `kernel/vmlinux.bin`; `config/guest-kernel-6.1.config` vendored from this build; no process for tracking 6.1 stable updates |
| EXT-06 Rootfs | **Partial** | `scripts/scrub-rootfs.sh` removes SSH keys/authorized_keys/sshd on a copy; `audit-rootfs.sh` PASS with `ALLOW_EOL=1`; SS1 PASS on scrubbed copy | Still Ubuntu 18.04 (EOL); root login shell remains. Needs a minimal rebuilt image |
| EXT-03 Jailer | **Not done** | `bin/jailer` pinned; `scripts/launch-jailed.sh` written | **Untested** (needs root). Supervisor still launches FC directly; needs `--api-sock`/vsock paths inside the chroot |
| EXT-08 Host posture | **Not done** | n/a | Dedicated host, separate accounts, read-only artifacts: operational |
| Guest sandbox / control-channel review | **Not done** | n/a | Still needs a human reviewer (see `SECURITY_REVIEW.md` §2) |

## Run it

```bash
export ANCHOR_KEY_FILE=/path/outside/repo/key   # mode 0600, >= 32 bytes
KERNEL=$PWD/kernel/vmlinux-hardened.bin ROOTFS=$PWD/rootfs/05-rootfs-hardened.ext4 \
  ./scripts/05-boot-attack.sh default   # and: kill
```

## Pentest notes

- Build artifacts (`kernel/*.bin`, `rootfs/*.ext4`) are gitignored; they exist locally only.
- Reproduce a check: `scripts/audit-kernel-config.sh kernel/linux-6.1.167/.config`,
  `ALLOW_EOL=1 scripts/audit-rootfs.sh rootfs/05-rootfs-hardened.ext4`,
  `scripts/verify-inputs.sh --installed`.
- Personal-device work: `docs/PORTABILITY.md` is a plan. Nothing beyond Linux x86_64 is built.
