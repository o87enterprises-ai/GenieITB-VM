# GenieITB-VM: External Attack Surface Review and Device Portability Assessment

| | |
|---|---|
| **Repository** | `o87enterprises-ai/GenieITB-VM` |
| **Reviewed at** | commit `d04e988` (branch `main`) |
| **Date** | 2026-11-08 |
| **Audience** | Code reviewers and the engineers applying the fixes |
| **Question asked** | Can this build withstand an outside-in, multi-agent CVE-chain or zero-day attack? What needs patching? Can it move to personal devices? |

---

## 1. Summary

**Verdict: this build should not be relied on to stop an outside-in attack.** It is a
containment demo for untrusted code *inside* a guest, and the repo says so. The
outward-facing design in `HANDOFF_PERIMETER.md` has not been built.

The VM is currently unreachable from the network for one reason: no NIC is attached.
That is a real and valuable property, but nothing enforces it, and it ends the moment
a network interface is added.

No system can promise to stop a true zero-day in the hypervisor or kernel. The
realistic goal is to make a chain longer, noisier and recorded in a way the attacker
cannot rewrite. Today, the host-side layers that would do that are missing or out of
date.

| ID | Finding | Severity | Effort |
|---|---|---|---|
| EXT-01 | No perimeter exists; the no-network property is unenforced | **Critical** before any NIC is added | High |
| EXT-02 | Firecracker is nine minor releases behind | **High** | Low to medium |
| EXT-03 | Firecracker runs without the jailer | **High** | Medium |
| EXT-04 | Receipts are unkeyed and have no out-of-band anchor | **High** | Low to medium |
| EXT-05 | Build inputs are downloaded without verification | **High** | Low |
| EXT-06 | Guest image is end-of-life and carries SSH material | **Medium** (High once networked) | Medium |
| EXT-07 | Guest kernel is broader than the workload needs | **Medium** | Medium |
| EXT-08 | Host posture does not match a hardened deployment | **Medium** | Medium |

**Recommended order:** EXT-05, EXT-02, EXT-03, EXT-04, EXT-06, EXT-07, EXT-08, then
EXT-01. Upgrade Firecracker *before* adopting the jailer (see EXT-03). EXT-01 is last
only because it depends on the others; no NIC should be attached until it is complete.

---

## 2. Scope and limits

**Covered:** the external and host-side surface: VMM version and launch configuration,
supply chain, receipt trust, guest image and kernel configuration, and host posture.

**Not covered: review these separately.** This document does not assess the
effectiveness of the in-guest sandbox or the guest-to-host control channel. An analysis
of that area was started during this review but not completed, so **the absence of
findings here must not be read as a clean result.** Please give these files a dedicated
review by a human security reviewer:

| File | Area |
|---|---|
| `scripts/05-seccomp-deny.h` | Syscall filter design and completeness |
| `scripts/05-shell_agent.c`, `scripts/05-doc_agent.c` | Landlock rulesets, privilege level, failure handling |
| `scripts/05-supervisor.c` | PID 1 duties, tripwire logic, control-channel parsing |
| `scripts/05-supervisor.py` | vsock listener, message handling, exit status |
| `~/MonkeyITM-VM` (`broker`) | Sibling repo; only `verify_against` was looked at here |

`HANDOFF_REVIEWER.md` already lists suggested scope for this work. Follow the project's
existing P6 rule: control-validation tests that attempt an action and assert the
denial and receipt.

**How findings were checked:** by reading source, inspecting the built kernel
`.config` and the rootfs image read-only, comparing binary hashes against the upstream
release, and checking public advisories. No exploitation was attempted, and no VM was
booted for this review.

---

## 3. How an outside-in chain maps to this build

| Attack stage | What should stop it | State today |
|---|---|---|
| Reach the workload over the network | Ingress broker, default deny | No NIC, so no path. No broker either (EXT-01) |
| Compromise the host or dev machine | Host hardening, least privilege | Development WSL2 host (EXT-08) |
| Poison the build | Pinned, verified inputs | Not verified (EXT-05) |
| Exploit the VMM | Current VMM, jailer | Old VMM, no jailer (EXT-02, EXT-03) |
| Exploit the guest once reachable | Minimal, patched guest | EOL userland, broad kernel (EXT-06, EXT-07) |
| Exfiltrate or pivot | Egress broker | Not built (EXT-01) |
| Erase the evidence | Keyed, anchored receipts | Not anchored (EXT-04) |

For a multi-agent attacker, the important property is that each stage can be worked in
parallel and known CVEs are cheap to try. Running current versions and verifying inputs
removes the cheapest stages first.

---

## 4. Findings

### EXT-01: No perimeter exists; the no-network property is unenforced

**Severity:** Critical before any NIC is added. **Locations:**
`HANDOFF_PERIMETER.md`; `scripts/05-supervisor.py:156-164`;
`scripts/01-boot-reference.sh:19`.

**Issue.** The boot sequence configures boot source, drive, machine config and vsock,
and no network interface. Isolation comes from that omission alone. Nothing fails the
build or the run if a later change adds one. The guest kernel has
`CONFIG_VIRTIO_NET=y` and `CONFIG_INET=y`, so it would use a NIC as soon as one appears.
There is no ingress broker, egress broker, `policy.yaml`, or per-agent isolation.

**Impact.** One configuration change would expose the guest directly, with no filtering
in front of it and no record of what crossed the boundary. Any later guest weakness then
becomes remotely relevant.

**Remediation.**
1. Add a run-time check now: after boot configuration, query Firecracker's VM config and
   abort if any network interface is present and no signed policy permits it.
2. Compile `VIRTIO_NET` out of the guest kernel until the broker exists.
3. Build `HANDOFF_PERIMETER.md` P0 to P6 in order. Keep egress control a priority.
4. Write the broker in a memory-safe language and treat all inbound input as hostile.

**Acceptance.** A test adding a NIC without policy aborts the run; P1 and P6 "green"
criteria in `HANDOFF_PERIMETER.md` pass.

---

### EXT-02: Firecracker is nine minor releases behind

**Severity:** High. **Locations:** `scripts/00-install-host.sh:5`; `bin/firecracker`.

**Issue.** The repo pins v1.8.0. The current release is v1.17.0 (published 2026-09-10).
The binary's SHA-256 matches the official v1.8.0 release, so this is an age problem and
not a tampering problem.

| Advisory | Component | Applies to v1.8.0? |
|---|---|---|
| CVE-2026-1386 (GHSA-36j2-f825-qvgc) | Jailer symlink handling, local host file overwrite. Affects ≤ 1.13.1 and 1.14.0 | **Yes, once the jailer is used.** The jailer is not used today |
| CVE-2026-5747 (GHSA-776c-mpj7-jm3r) | Virtio PCI transport out-of-bounds write. Affects 1.13.0 to 1.14.3 and 1.15.0 | No, v1.8.0 is below the affected range |

Confirm ranges against the GitHub advisories before closing this item, since secondary
trackers disagreed on one version boundary. Also check whether v1.8.0 is still inside
upstream's support window; if not, unpublished fixes may never reach it.

**Remediation.** Move to a current supported release, and pin it by version and hash
(EXT-05). Re-run the SS1 default and kill modes, and retest the API calls in
`05-supervisor.py`, which may have changed across releases. Add a recurring check of
Firecracker advisories.

**Acceptance.** `firecracker --version` reports a supported release; both SS1 modes pass.

---

### EXT-03: Firecracker runs without the jailer

**Severity:** High. **Locations:** `scripts/05-supervisor.py:152`;
`HANDOFF_REVIEWER.md` (F10).

**Issue.** Firecracker launches directly as the developer's user, with no chroot, no
dedicated UID, and no cgroup limits. Its built-in seccomp filter is still active because
`--no-seccomp` is not passed. If the VMM were compromised, the attacker would hold
everything that user can reach, including the source tree and receipts.

**Corrections to existing guidance.**
- `HANDOFF_REVIEWER.md` recommends passing `--seccomp-level 2`. This binary's `--help`
  lists only `--no-seccomp` and `--seccomp-filter`. Remove that flag from the runbook.
- **Upgrade before adopting the jailer**, because v1.8.0 falls in the CVE-2026-1386 range.

**Remediation.** Launch through `jailer` with a dedicated UID and GID, chroot base
directory, cgroup v2 CPU and memory limits, and a new PID namespace. Copy or hard-link
the kernel and rootfs into the chroot. Keep the receipt writer outside the jail. Make
sure jailer directories are not writable by untrusted users.

**Acceptance.** `/proc/<pid>/status` shows the dedicated UID, the VMM's root is the
chroot, cgroup limits apply, and both SS1 modes pass.

---

### EXT-04: Receipts are unkeyed and have no out-of-band anchor

**Severity:** High. **Locations:** `scripts/04-receipt.py:55-60`,
`scripts/04-receipt.py:91-105`; `scripts/05-boot-attack.sh:23`,
`scripts/05-boot-attack.sh:52`; `HANDOFF_REVIEWER.md` (F8).

**Issue.** The chain is plain SHA-256 with no secret, so anyone with write access to the
database can rewrite it and recompute valid hashes. Verification walks forward from
genesis and has no expected end point, so a shortened chain still passes. `05-boot-attack.sh`
also deletes the previous receipt at the start of each run.

**Impact.** An outside attacker who reaches the host can remove evidence of the intrusion
and leave a chain that verifies. As `HANDOFF_PERIMETER.md` puts it, a chain without an
anchor "is a log, not evidence."

**Remediation.**
1. After each run, publish the head hash and row count somewhere the host user cannot
   rewrite: a remote append-only store or a transparency log.
2. Call the existing anchored check. `verify_against(head, rows)` already exists at
   `MonkeyITM-VM/log/src/lib.rs:749`; wire it into the run script.
3. Sign or HMAC chain heads, with the key held outside the VM and ideally in hardware
   (TPM). A key held by the same host user only adds limited protection.
4. Archive prior receipts rather than deleting them.

**Acceptance.** Tests that truncate, edit, or wholesale recompute a copy of a receipt
are each rejected by anchored verification.

---

### EXT-05: Build inputs are downloaded without verification

**Severity:** High. **Locations:** `scripts/00-install-host.sh:30`,
`scripts/00-install-host.sh:42-43`, `scripts/00-install-host.sh:66-67`,
`scripts/00-install-host.sh:74-75`; `scripts/04-build-kernel.sh:7`,
`scripts/04-build-kernel.sh:26-27`, `scripts/04-build-kernel.sh:36`.

**Issue.**

| Input | Line | Problem |
|---|---|---|
| Rustup installer | `00-install-host.sh:30` | Piped directly into `sh` |
| Firecracker tarball | `00-install-host.sh:42-43` | Upstream publishes a `.sha256.txt`; it is not checked |
| Reference kernel | `00-install-host.sh:66-67` | Fetched from S3 with no hash |
| Reference rootfs | `00-install-host.sh:74-75` | Fetched from S3 with no hash |
| Linux source | `04-build-kernel.sh:26-27` | Upstream signature not verified |
| Kernel config | `04-build-kernel.sh:7`, `:36` | Fetched from the moving `main` branch, so builds are not reproducible |

Prebuilt binaries are also committed to the repo (`bin/firecracker`,
`guest-agent/agent`), and the sibling `broker` binary is trusted by path.

**Impact.** Whoever can alter any of these inputs controls the VMM, kernel, or guest,
and every later check runs on top of that compromised base. This is an inexpensive stage
for an attacker.

**Remediation.** Keep a checked-in lockfile of URL plus SHA-256 for every input, and
fail closed on mismatch. Verify the kernel's PGP signature. Pin the config to a commit
or vendor it. Build rootfs images from a reproducible recipe and record their hashes.
Remove committed binaries or document their provenance. Add CI that rebuilds and
compares hashes.

**Acceptance.** Altering one byte of any input stops the build.

---

### EXT-06: Guest image is end-of-life and carries SSH material

**Severity:** Medium, High once networked. **Location:** `rootfs/05-rootfs.ext4`
(gitignored; derived from the image at `00-install-host.sh:75`).

**Issue.** The rootfs derives from the Ubuntu 18.04 "bionic" quickstart image, dated
August 2021. It contains `/etc/ssh/sshd_config`, private SSH host keys, and
`/root/.ssh/authorized_keys`. Those keys come from a publicly downloadable image, so they
should be treated as public. Its userland is a full distribution that the workload does
not need. The current `/init` does not start sshd, so this is latent today.

**Remediation.** Replace it with a minimal, purpose-built image: static binaries plus
only what they require. Remove all SSH material and credentials. If a broader userland
is needed, use a supported distribution and a defined patch process.

**Acceptance.** An inventory of the image lists only expected files; no keys or
`authorized_keys` exist; a scan reports no EOL packages.

---

### EXT-07: Guest kernel is broader than the workload needs

**Severity:** Medium. **Locations:** `kernel/linux-6.1.167/.config`;
`scripts/04-build-kernel.sh:51-68`.

**Issue.** The kernel is built from a general-purpose Firecracker config. `CONFIG_LSM`
names `lockdown` and `yama`, but both are compiled out (`CONFIG_SECURITY_LOCKDOWN_LSM`
and `CONFIG_SECURITY_YAMA` are unset), so the list suggests protection that is not
there. The build script checks that required options are on, and has no check that
unneeded ones are off. There is also no process for tracking 6.1 stable updates.

| Option | Current | Recommendation |
|---|---|---|
| `SECURITY_LOCKDOWN_LSM` | off | Enable, and enforce lockdown |
| `SECURITY_YAMA` | off | Enable |
| `SECURITY_DMESG_RESTRICT` | off | Enable |
| `INIT_ON_ALLOC_DEFAULT_ON` | off | Enable |
| `INIT_ON_FREE_DEFAULT_ON` | off | Enable if the cost is acceptable |
| `IA32_EMULATION` | on | Disable unless 32-bit binaries are needed |
| `USER_NS` | on | Disable unless required |
| `BPF_SYSCALL` | on | Disable unless required |
| `IO_URING` | on | Disable at build time |
| `USERFAULTFD` | on | Disable unless required |
| `CHECKPOINT_RESTORE` | on | Disable unless required |
| `DEBUG_FS` | on | Disable |
| `MAGIC_SYSRQ` | on | Disable |
| `KEXEC_FILE` | on | Disable |
| `UEVENT_HELPER` | on | Disable |
| `NETFILTER`, `PACKET`, `VIRTIO_NET`, `INET` | on | Disable until the perimeter build requires them |

Already in good shape: `MODULES`, `KEXEC`, and `DEVMEM` are off, and KASLR, strict kernel
RWX, hardened usercopy, and freelist hardening are on.

**Remediation.** Move from a general config to a small allowlisted one, and have the
build fail if a denied option is enabled. Check Firecracker's kernel support policy,
since the 6.1 support window may have changed. Rebuild on each 6.1 stable release, or
move to a supported newer LTS.

**Acceptance.** A config audit script passes in CI; both SS1 modes pass.

---

### EXT-08: Host posture does not match a hardened deployment

**Severity:** Medium for a demo, High for any deployment. **Location:** deployment
environment.

**Issue.**
- The host is WSL2 on a developer workstation (kernel `6.18.54.1-microsoft-standard-WSL2`),
  which adds nesting under Hyper-V. Firecracker's documentation describes physical Linux
  hosts.
- The running user belongs to `sudo` and `docker`. Either one makes a compromise of that
  account equivalent to root on the Linux host.
- The kernel, rootfs, supervisor, and receipts are all writable by that one account.
- An unrelated local service (Ollama, `127.0.0.1:11434`) shares the host.
- No API socket restriction is applied beyond a private temp directory, and the API
  stays active for the VM's lifetime.

**Remediation.** For anything beyond the demo, use a dedicated physical Linux host and
follow Firecracker's production host setup guide. Use separate accounts for build, VMM,
and receipts, with none in `docker` or `sudo`. Make boot artifacts read-only to the VMM
account. Consider API-less launch (`--no-api --config-file`) so no control socket exists
after start.

**Acceptance.** A written host baseline exists and a script verifies it before launch.

---

## 5. Device portability assessment

### 5.1 Conclusion

**Porting this exact build to every device class is not viable, but a shared core with
platform-specific backends is.** The build needs Linux, KVM, and a workable amount of RAM.
Desktops can meet that, or get close. iPhones and iPads cannot, and stock Android and
most consumer routers do not offer it to an ordinary installed product.

The device-independent value is the broker model: default deny, mediated ingress and
egress, and verifiable receipts. On restricted devices, ship that without a VM, and state
clearly that it is a lesser protection.

### 5.2 Platform matrix

| Platform | Firecracker as built | Realistic path | Rating |
|---|---|---|---|
| **Linux desktop or laptop, x86_64** | Yes, needs `/dev/kvm` | Direct port with EXT-01 to 08 fixed | **Strong** |
| **Linux desktop or SBC, aarch64** | Yes in principle | Recompile, port x86-specific code, test on real hardware | **Good** |
| **Windows desktop** | Only through WSL2 nesting | WSL2 for early use, then a Windows hypervisor backend | **Moderate** |
| **macOS** | No, there is no KVM | New backend on Apple's Virtualization framework; Linux guest stays | **Moderate** |
| **Android phone or tablet** | No for store apps | Preinstall or OEM partnership for VMs; otherwise broker-only | **Limited** |
| **iPhone or iPad** | No | Broker-only, with no VM claims | **VM not feasible** |
| **Consumer Wi-Fi router** | Generally no | Broker-only firmware on capable hardware | **VM unlikely; broker promising** |
| **x86 or high-end ARM "software router"** | Possible where KVM works | Dedicated appliance build | **Moderate** |

### 5.3 Platform notes

**Linux desktop.** This is the natural first target. The main issues are packaging,
automatic security updates, and KVM group access without giving users broad privileges.

**aarch64 Linux.** Firecracker supports aarch64 hosts, with some feature differences from
x86_64. The repo has x86-specific code to port: `scripts/05-doc_agent.c:33` reads
`REG_RDI`, and all binaries, the kernel, and the rootfs are x86_64.

**Windows.** This repo already runs under WSL2, so a demo is straightforward. It depends
on nested virtualization and on the user enabling WSL2, which makes it less suitable as a
security product for general users. A production version needs a native backend.

**macOS.** Replace the VMM layer with a backend built on Apple's frameworks, which needs
the hypervisor entitlement. The Linux guest and its Landlock and seccomp configuration can
carry over on Apple silicon as an aarch64 build. The Firecracker jailer and its host-side
controls do not carry over and need a macOS equivalent.

**Android phones and tablets.** The Android Virtualization Framework exists, and pKVM is
part of the Generic Kernel Image work. However, the framework APIs are `@SystemApi` and
require `MANAGE_VIRTUAL_MACHINE`, which AOSP documents as restricted to privileged or
preinstalled apps, with `adb pm grant` available for development. That means a Play Store
app cannot rely on it. Device support also varies. Options are an OEM or preinstall
partnership, or a broker-only app, for example built on Android's `VpnService`.

**iPhone and iPad.** Apple documents Hypervisor.framework for macOS only. The evidence
found for iOS and iPadOS is community reports that it is unavailable, and jailbreak-only
experiments, which are not a product path. Confirm against current Apple documentation
before finalizing this. A broker-only design using Apple's Network Extension framework is
the realistic option. App Store rules and the iOS process model prevent a supervisor
spawning sandboxed child processes as this repo does. Do not market this as VM isolation.

**Consumer Wi-Fi routers.**
- Firecracker requires little-endian x86_64 or aarch64, which rules out MIPS and 32-bit
  ARM devices.
- This build allocates 256 MiB to the guest alone (`05-supervisor.py:162`), which is more
  than many routers can spare.
- Whether a given ARM64 router exposes hardware virtualization to the OS could not be
  confirmed in general, and needs checking per device.
- Vendor firmware is usually locked, so installation may require OpenWrt or a vendor
  partnership.

A router is nevertheless the logical home for the **broker**, since it already sits on the
network boundary and could protect devices that cannot run this themselves. It would also
become a single, high-value, internet-facing target. It would need a memory-safe
implementation, signed automatic updates, and a safe failure mode.

### 5.4 What carries over

| Component | Portability |
|---|---|
| Policy schema (planned `policy.yaml`) | All platforms |
| Receipt format and hash chain | All platforms |
| `broker` (Rust) | Most platforms, needs cross-compiling and per-OS integration |
| vsock control-channel pattern | Where a VM exists; the transport may differ |
| Landlock and seccomp layer | Linux guests; availability on Android must be verified |
| Python supervisor | Desktop only; replace with Rust for other targets |
| Firecracker and jailer launch | Linux with KVM only |
| Guest C agents | Linux guests, after aarch64 porting |

### 5.5 New requirements for personal devices

Going consumer changes the threat model, because there is no operator watching the system.

- **Automatic signed updates** become mandatory. A security product that ages in place, as
  in EXT-02, becomes a liability.
- **Hardware-backed keys** (TPM, Secure Enclave, Android Keystore or StrongBox) should hold
  receipt signing keys.
- **Off-device anchoring** requires a service, which raises privacy and data-handling
  questions.
- **Battery, memory, and thermal limits** apply. Per-agent microVMs may not be practical on
  phones.
- **Usable alerts and safe failure** are needed. A tripwire that halts things must not cut
  someone off from emergency connectivity or the rest of their network.
- **Honest claims per platform.** A broker-only iOS app does not provide what a microVM on
  Linux provides. The scope statement in `HANDOFF_PERIMETER.md` should be adapted per
  platform.

### 5.6 Recommended roadmap

1. Complete the separate guest and channel review (section 2), and close EXT-02 to EXT-08.
2. Build the perimeter (EXT-01) on Linux x86_64.
3. Extract a VMM abstraction, replace the Python supervisor with Rust, and add aarch64.
4. Add macOS and Windows backends.
5. Build a broker-only appliance for capable routers or small boards.
6. Build broker-only mobile apps, and pursue Android OEM access only if there is demand.

Validate each step before starting the next. The perimeter work in step 2 is what gives
every later platform something worth porting.

---

## 6. Reviewer checklist

- [ ] EXT-05 Lockfile of hashes in place; tampered input stops the build
- [ ] EXT-02 Firecracker upgraded to a supported release and pinned
- [ ] EXT-03 Jailer in use; `--seccomp-level` removed from runbooks
- [ ] EXT-04 Anchored verification wired in; truncation and recompute tests rejected
- [ ] EXT-06 Minimal rootfs; no SSH material
- [ ] EXT-07 Allowlisted kernel config enforced in CI
- [ ] EXT-08 Host baseline written and verified at launch
- [ ] EXT-01 NIC guard added now; perimeter P0 to P6 complete before any NIC is attached
- [ ] Separate review of guest sandbox and control channel completed (section 2)
- [ ] `broker` source reviewed (sibling repo)

---

## 7. Sources

Firecracker:
- [NVD: CVE-2026-1386](https://nvd.nist.gov/vuln/detail/cve-2026-1386)
- [AWS Security Bulletin 2026-003](https://aws.amazon.com/de/security/security-bulletins/2026-003-AWS/)
- [NVD: CVE-2026-5747](https://nvd.nist.gov/vuln/detail/CVE-2026-5747)
- [GCVE: CVE-2026-5747](https://db.gcve.eu/vuln/cve-2026-5747)
- [Nixpkgs security tracker: Firecracker](https://tracker.security.nixos.org/suggestions/by-package/firecracker)
- [Firecracker getting started](https://www.GitHub.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
- [Firecracker kernel policy](https://www.github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md)

Android:
- [AVF framework API README](https://android.googlesource.com/platform/packages/modules/Virtualization/+/750574560/libs/framework-virtualization/README.md)
- [Try Android Virtualization Framework](https://source.android.google.cn/docs/core/virtualization/tryavf?hl=en)

Apple:
- [Apple Hypervisor framework documentation](https://developer.apple.com/documentation/hypervisor.md)
- [UTM discussion on iPadOS virtualization](https://www.github.com/utmapp/UTM/discussions/5748)
- [Jailbreak-based hypervisor experiment](https://worthdoingbadly.com/hv/)

Routers:
- [OpenWrt forum: virtualization on arm64](https://forum.openwrt.org/t/virtulization-on-arm64/163091)
- [OpenWrt in QEMU](https://openwrt.org/docs/guide-user/virtualization/qemu.)

Platform notes on Android `VpnService` and Apple's Network Extension come from general
platform knowledge and were not re-checked for this document.
