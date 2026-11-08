# Personal-device adaptation plan

Status: **plan only. No non-Linux/x86_64 port has been built or tested.** This host is
WSL2 on x86_64 with no root. Claims below are design intent plus what public platform docs
say (see `SECURITY_REVIEW.md` §5 for sources and caveats).

## Principle

Do not port the demo. Extract the part that is device-independent, and give each platform
the strongest isolation it actually allows, labelled honestly.

```
        policy.yaml  (what may enter / leave)         ← portable
              │
        broker (Rust)  decide · perform · record      ← portable
              │
        receipt chain + keyed anchor                  ← portable (anchor.py → Rust)
              │
   ┌──────────┴───────────── Isolation backend (trait) ─────────────┐
   │ firecracker   avf/macOS-vz   hyper-v/wsl2   android-avf   none │
   └─────────────────────────────────────────────────────────────────┘
```

## Backend trait (first code to write)

`Isolation { boot(spec) -> Handle; attest() -> Level; control() -> Channel; kill(); }`

`attest()` returns one of: `MicroVM` · `ProcessSandbox` · `BrokerOnly`. **Every receipt
records the level**, and UI/marketing must quote it. A `BrokerOnly` device must never be
described as VM-isolated.

## Platform ladder

| Order | Target | Backend | Isolation level | Blocking unknowns |
|---|---|---|---|---|
| 1 | Linux x86_64 desktop/server | firecracker + jailer | MicroVM | none beyond EXT-01..08 |
| 2 | Linux aarch64 (SBC, laptop) | firecracker | MicroVM | port `05-doc_agent.c` (`REG_RDI` is x86), aarch64 kernel + rootfs, real-hardware test |
| 3 | macOS (Apple silicon) | Apple Virtualization framework, Linux aarch64 guest | MicroVM | needs entitlements + signing; host controls differ from jailer |
| 4 | Windows | Hyper-V/WSL2 backend | MicroVM (nested) | nested virt availability; WSL2 is a demo path, not a product path |
| 5 | Router / small ARM64 box | broker only, OpenWrt-class firmware | BrokerOnly | per-device: little-endian 64-bit, RAM (guest alone is 256 MiB), EL2/KVM exposed? firmware locked? |
| 6 | Android | broker via `VpnService`; VM only via OEM/preinstall (AVF permission is privileged) | BrokerOnly (VM if OEM) | OEM access; pKVM device support varies |
| 7 | iOS / iPadOS | broker via Network Extension | BrokerOnly | no public hypervisor API found for third-party apps; re-verify per release |

## What each tier needs before it ships

1. **Signed, automatic updates.** The repo's own EXT-02 (a pinned VMM nine releases stale)
   is the failure mode this prevents. No update channel → no consumer release.
2. **Hardware-backed keys** for receipt MACs (TPM / Secure Enclave / Keystore).
3. **Off-device anchor** service with a stated privacy policy (what leaves the device).
4. **Fail-safe tripwire.** A halt must not strand the user's connectivity; define the
   safe-failure mode per platform (e.g. router fails open to the user's chosen default only
   if they opt in).
5. **Per-platform scope statement**, derived from `attest()`, replacing the single
   statement in `HANDOFF_PERIMETER.md`.

## Router note

The broker is the right thing to put on a router (it already sits at the boundary). It is
also then an internet-facing single point of failure: memory-safe implementation, signed
updates, and a pen test of the broker itself come before any router firmware is offered.

## Gates (do not start the next tier until the previous passes)

- Tier 1: `SECURITY_REVIEW.md` checklist all ticked; independent pentest findings closed.
- Tier 2+: same SS1 acceptance (`05-boot-attack.sh` default + kill), plus
  `anchor.py` truncate/rewrite rejection, run on real hardware for that tier.
- `BrokerOnly` tiers: P6 control-validation tests from `HANDOFF_PERIMETER.md` against the
  real platform network API (denied ingress, denied egress, denied lateral reach), not an
  emulator.
