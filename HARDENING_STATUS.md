# Hardening status (branch `hardening/ext-review`, base `d04e988`)

Date: 2026-11-08. Host: WSL2 x86_64. Nothing here has been independently pentested.

| ID | State | Evidence | Not done / caveat |
|---|---|---|---|
| EXT-02 Firecracker | **Done** | v1.17.0, tarball SHA-256 matches upstream `.sha256.txt`; SS1 default+kill PASS | Re-check advisories GHSA-36j2-f825-qvgc, GHSA-776c-mpj7-jm3r on GitHub (ranges came from secondary trackers) |
| EXT-05 Supply chain | **Mostly done** | `inputs.lock` has no `TODO` left: FC, jailer, kernel source, vendored config, and reference images are pinned and verified at use; `curl\|sh` removed. Kernel hash matched kernel.org's list, whose autosigner PGP signature was checked by hand | The build scripts check the pinned hash, not PGP. `guest-agent/agent` and the `broker` binary are pinned as found, so changes are detected, but their provenance was not established |
| EXT-04 Receipt anchor | **Done in code** | `scripts/anchor.py`: truncation, same-length forge, tampered anchor log, loose key perms all rejected (plain `verify` accepted the forge); SS1 run script requires it by default; old receipts archived not deleted | Protection exists only if key + anchor log sit behind a different privilege boundary than the receipt writer. Use `ANCHOR_PUSH_CMD` to a remote append-only store |
| EXT-01 NIC guard | **Done (guard only)** | Supervisor aborts on any NIC/MMDS in `/vm/config` before `InstanceStart`; unit-tested with stubbed configs | Not tested against a real NIC (needs tap/root). The perimeter now lives in `../GenieITB-Perimeter` and needs no NIC: keep this guard. It has not been pentested or run together with the jail |
| EXT-07 Guest kernel | **Done** | `scripts/audit-kernel-config.sh` PASS; hardened kernel promoted to `kernel/vmlinux.bin` (previous saved as `kernel/vmlinux-prehardening.bin.bak`); boot log shows `capability,landlock,lockdown,yama`; SS1 default+kill PASS | No process for tracking 6.1 stable updates |
| EXT-06 Rootfs | **Done** | `scripts/build-minimal-rootfs.sh` builds a 16 MiB image from static binaries only (no distro, shell, or SSH), without root; now the run-script default; `audit-rootfs.sh` PASS without `ALLOW_EOL`; SS1 default+kill PASS | The image is gitignored: build it locally |
| EXT-03 Jailer | **Done on WSL2** | `JAIL_USER=fcjail ./scripts/05-boot-attack.sh`: VMM under jailer with dedicated uid, chroot, PID namespace, cgroup v2 limits. The supervisor checks these on the live VMM and aborts on mismatch. Only launch/teardown keep root; guest-data handling drops to the invoking user. SS1 default+kill PASS, clean exit, no leftover jail or cgroup | Not the default: unjailed unless `JAIL_USER` is set. Scripts started via sudo live in a user-writable repo; install them root-owned for any deployment. Not yet tested on a physical Linux host |
| EXT-08 Host posture | **Not done** | n/a | Dedicated host, separate accounts, read-only artifacts: operational |
| Guest agents | **Non-root** | Each agent runs under its own unprivileged uid and refuses to start if it cannot drop. A control build with Landlock disabled let the denied write succeed, so the DENY comes from Landlock, not file permissions. SS1 default+kill PASS | PID 1 supervisor remains root inside the guest |
| Guest sandbox / control channel (GEN-01..07) | **Fixed; re-review needed** | Agents use a seccomp allowlist and full-rights Landlock and exit if either fails to install; agents cannot open sockets; supervisor enforces a per-agent line grammar and counts kernel seccomp kills. `scripts/test-sandbox.sh` and `scripts/test-records.sh` pass in a real guest; a control run with the sandbox off fails them | A compromised agent can still stay silent about denials Landlock returns to it. PID 1 supervisor remains root. Reviewer has not seen this code |

## Run it

```bash
export ANCHOR_KEY_FILE=/path/outside/repo/key   # mode 0600, >= 32 bytes
./scripts/build-minimal-rootfs.sh       # once, or after changing guest code
./scripts/05-boot-attack.sh default     # and: kill
```

## Pentest notes

- Build artifacts (`kernel/*.bin`, `rootfs/*.ext4`) are gitignored; they exist locally only.
- Reproduce a check: `scripts/audit-kernel-config.sh kernel/linux-6.1.167/.config`,
  `scripts/audit-rootfs.sh rootfs/05-rootfs-minimal.ext4`,
  `scripts/verify-inputs.sh --installed`.
- Personal-device work: `docs/PORTABILITY.md` is a plan. Nothing beyond Linux x86_64 is built.
