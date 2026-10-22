<p align="center">
  <img src="assets/branding/logo.webp" alt="GenieITB-VM" width="420">
</p>

# GenieITB-VM

A minimal Firecracker microVM containment demo. Kernel-enforced Landlock +
seccomp confine untrusted agent processes inside the guest; every action —
allowed or denied — is written to a hash-chained, independently verifiable
receipt.

## What it proves

A two-stage untrusted "attack" (write a payload to disk, then exec it) is
denied end-to-end by the containment layer, in two run modes:

- **default** — both denials are recorded, the supervisor exits cleanly.
- **kill** — a configurable denial threshold (`denials>=3`) trips a
  tripwire and the supervisor kills the agent group mid-attack.

Every step — LSM stack, each `ALLOW`/`DENY`/`TRY` and its errno, and the
supervisor's own lifecycle — is appended to a SQLite-backed hash chain.
[`broker verify`](https://github.com/o87enterprises-ai/MonkeyITM-VM) checks
that the chain is intact and unmodified; `broker export` turns it into a
human-readable record of exactly what happened.

## Status

Phase 5 SS1 (containment demo) is complete and independently re-verified:
both run modes exit `0`, both receipts pass `broker verify`, and the full
acceptance checklist (correct Landlock/seccomp denial errno, no vacuous
EROFS denials, tripwire behavior) passes. See `HANDOFF_4.md` for the full
project history and findings.

## Running it

```bash
./scripts/05-boot-attack.sh default
./scripts/05-boot-attack.sh kill
```

Needs: a Linux host with `/dev/kvm`, the bundled `bin/firecracker`, a built
kernel at `kernel/vmlinux.bin`, the rootfs image at
`rootfs/05-rootfs.ext4`, and the `broker` binary from the sibling
[MonkeyITM-VM](https://github.com/o87enterprises-ai/MonkeyITM-VM) project
(`$HOME/MonkeyITM-VM/target/release/broker`, or set `$BROKER`).

## Scope

This is a defense-in-depth layer that reduces attack surface and produces
verifiable incident records. It does not claim to prevent all multi-agent
exploit chains, does not replace OS patches or EDR, and does not claim
100% anything. Claims are scoped to what the demo shows.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
