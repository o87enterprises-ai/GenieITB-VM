# HANDOFF — Independent Review / Pentest

**Repo:** https://github.com/o87enterprises-ai/GenieITB-VM (public, Apache 2.0)
**As of:** 2026-10-21, commit `093a17d`
**Status:** Phase 5 SS1 (containment demo) built and re-verified. An
independent review was then performed (findings F1–F11, tests T1–T9); the
remediation of that review is recorded in "Phase 2 remediation" at the
bottom of this file and lives on branch `security-review/phase-2`.

## What this project is

A minimal Firecracker microVM pipeline where two untrusted agent
processes attempt a two-stage attack (write a payload file, then exec
it), and a kernel-enforced containment layer (Landlock + seccomp) denies
both attempts. Every step — the LSM stack in use, each `ALLOW`/`DENY`/
`TRY` and its errno, and the supervisor's own lifecycle — is appended to
a hash-chained SQLite receipt. A separate `broker` binary (from the
sibling [MonkeyITM-VM](https://github.com/o87enterprises-ai/MonkeyITM-VM)
project) verifies the chain is intact and exports it to JSON/text.

Read `HANDOFF_4.md` first — it has the full build history, the five
numbered findings from building SS1 (Landlock stacking semantics, dynamic
ELF exec needing interpreter-load permission, securityfs not auto-mounted,
etc.), and the project's own stated scope/ethics.

## What has been verified, and how

I (the assistant that did this handoff) ran `scripts/05-boot-attack.sh`
for both `default` and `kill` modes, from a clean checkout, on 2026-10-21.
Both runs:

- Exit `0`.
- Pass `broker verify` (chain intact, unmodified).
- Pass every assertion in the script's §7 checklist: correct Landlock/
  seccomp denial errno (13, not a vacuous 30/EROFS), `HELLO`/`ALLOW`/`DENY`/
  `TRY` lines present and ordered correctly, tripwire fires at exactly 3
  denials in kill mode and is absent in default mode.

I also found and fixed one cosmetic issue: `scripts/05-shell_agent.c` had
`/usr/lib64` in its Landlock allowlist, which doesn't exist on this
Ubuntu 18.04 rootfs and produced a harmless but noisy `ERROR` line on
every run. Fixed, rebuilt, reinstalled, re-verified clean (commit
`0e1ca52`).

**That is the entire extent of testing done so far.** It is functional
verification of one scripted attack path against a known allowlist — it
is not a security review. Nobody has:

- Tried to break out of the Landlock ruleset (other syscalls, other
  target paths, symlink/race tricks, etc.)
- Fuzzed the supervisor, the agents, or the vsock protocol between them
- Attacked the receipt chain's integrity directly (DB file, broker binary)
- Reviewed the C code in `scripts/05-*.c` for memory safety or logic bugs
  beyond what the checklist happens to exercise
- Load-tested, resource-exhausted, or tried concurrent/racing attack
  attempts
- Looked at the host-side attack surface (Firecracker config, vsock
  device, supervisor's Python control code) from an adversarial angle

## Suggested scope for this review

1. **Landlock/seccomp bypass** — can `shell_agent` or `doc_agent` reach
   anything outside their intended allowlist (`/bin`, `/usr/bin`, `/lib`,
   `/lib64`, `/usr/lib`, `/usr/local/lib` for exec; see `05-shell_agent.c`
   / `05-doc_agent.c` for the exact rulesets)? Known-intentional gap:
   `/tmp` is outside the exec allowlist by design — that's the thing
   being denied.
2. **Supervisor/agent code review** (`scripts/05-supervisor.c`,
   `05-shell_agent.c`, `05-doc_agent.c`) — buffer handling in `report()`
   (fixed 1024/512-byte stack buffers, `snprintf`-bounded but worth a
   look), the vsock read/ack loop, TOCTOU between checks and action.
3. **Receipt chain integrity** — can the hash chain in
   `logs/05-attack-*.db` be forged or truncated without `broker verify`
   catching it? (`broker` source is in the sibling MonkeyITM-VM repo,
   not in this one.)
4. **Host-side surface** — `scripts/05-supervisor.py` (Firecracker launch,
   vsock plumbing, timeout handling), `config/` files, decoy-payload
   pre-staging logic.
5. **Kill-switch logic** — can an agent avoid the denial-count threshold
   or survive the group kill?

## Explicitly out of scope / not built

- **SS2** (feeding live LLM-generated attack payloads through this
  pipeline) is *not built*. It's documented as a future direction in
  `HANDOFF_4.md` §Next but no code exists for it in this repo, and none
  was written by the assistant that produced this handoff — that's being
  built separately, by the project owner, outside this session.
- No fuzzing harness, no CI, no automated adversarial testing exists yet.

## Reproducing the SS1 runs yourself

Needs a Linux host with `/dev/kvm`. On the dev machine this was built on,
it runs under WSL2 Ubuntu.

```bash
git clone https://github.com/o87enterprises-ai/GenieITB-VM.git
cd GenieITB-VM
# broker comes from the sibling MonkeyITM-VM repo (private) — build it
# there first, or point $BROKER at an existing binary.
./scripts/05-boot-attack.sh default ; echo "exit=$?"
./scripts/05-boot-attack.sh kill    ; echo "exit=$?"
```

Expected: both exit `0`, output ends with `Phase 5 SS1 (<mode>) PASS`,
and the printed "vsock lines, in order" block has no `ERROR` lines and
no `errno=30`.

Rootfs images (`rootfs/*.ext4`) and the kernel source tree
(`kernel/linux-6.1.167/`) are gitignored — they're large, regenerable
build artifacts. `rootfs/05-rootfs.ext4` and `kernel/vmlinux.bin` must
exist locally to run the demo; see `HANDOFF.md`/`HANDOFF_3.md` for how
they were built if you need to regenerate them.

## Ethics / scope statement (from the project owner, verbatim)

> This is a **defense-in-depth layer** that **reduces attack surface** and
> produces **verifiable incident records**. It does **not** claim to
> prevent all multi-agent exploit chains, does not replace OS patches or
> EDR, and does not claim 100% anything. Claims are scoped to what the
> demo shows.

Fake secrets only; zero egress (per the project's Phase 1).

---

# Phase 2 remediation (branch `security-review/phase-2`)

An independent review (findings F1–F11 / tests T1–T9) was supplied. Its
cited commits (`8fdb03e`, `688782e`), branch (`security-review/phase-1`),
and helper scripts (`write-anchor.sh`, `verify-with-anchor.sh`) did **not**
exist in this repository — they described a workspace that was never
committed here. So every fix below was applied fresh against the real
tree, and each finding was re-checked against the actual source before
acting. Two of the review's findings did not survive that check; they are
marked below.

**Both SS1 modes still PASS after every change** (`broker verify` intact,
full §7 checklist green, tripwire fires at exactly 3 denials in kill mode).

| ID | Review sev | Verdict here | What changed |
|---|---|---|---|
| F1 | P1 | **Fixed** | `report()` in both agents clamped `snprintf` return before `write()` (it was **not** actually fixed in this repo despite the review's "FIXED" note). Not triggerable by SS1's ≤300B lines; fixed as latent OOB-read hardening. |
| F2 | P0 (latent) | **Fixed** | New `scripts/05-seccomp-deny.h`; both agents now deny `socket(AF_UNIX)` via seccomp. shell_agent keeps `execve` **un-trapped** so Landlock stays the EXECUTE gate and the denial remains `errno=13`. Confirmed live by T8. |
| F3 | P2 | **Fixed** | Host vsock reader records an explicit `TRUNCATION` chain event and refuses to ack instead of committing a truncated line as whole. The guest `send_and_ack` already fails closed on a missing ack, so no agent change was needed. Genuinely latent: real lines are ≤1024B. |
| F4 | P2 | Documented | Connection-flood bound unchanged (`listen(8)` + 1s–5s timeout). Out of scope for the 60s single-shot demo; noted for the mobile port. |
| F5 | P2 | **Fixed (with correction)** | Tripwire now counts by a positive non-denial allowlist. **The review's proposed allowlist omitted `TRY`**, which would have counted every attempt as a denial and tripped the wire early; `TRY` is included here, and kill mode still trips at exactly 3. |
| F6 | P3 | **Not a bug (false positive)** | `spawn()` already does `if (sv[1] != 3) close(sv[1]);` — no fd leak. No change. |
| F7 | P3 | **Fixed** | `ack[16]` zero-initialized. |
| F8 | P1 (def-in-depth) | **Not done** | The anchored-verify workflow and its scripts do not exist in this repo. `broker`'s `--head/--rows` anchoring is a sibling-repo capability; wiring it belongs in its own change, not bundled here. Left open. |
| F9 | P2 | **Fixed** | Same seccomp header denies `io_uring_{setup,enter,register}`. Confirmed by T8. |
| F10 | P2 (host) | **Documented, not wired** | Firecracker is still launched without the jailer. Wiring the jailer needs root, a chroot-base-dir, and copying kernel+rootfs into the chroot — it would destabilize the working demo and is an operational/deployment change, not a code fix. Recommended for any non-demo deployment: `jailer --id <id> --exec-file firecracker --uid <uid> --gid <gid> --chroot-base-dir <dir> --cgroup-version 2 -- --seccomp-level 2 --api-sock <sock>`. |
| F11 | — | N/A | Review artifact only. |

## New review assets in this branch

- `scripts/05-seccomp-deny.h` — shared agent syscall deny-list (F2/F9).
- `scripts/05-seccomp-probe.c` — **T8** control-validation test (not an
  exploit): installs the shell_agent profile and asserts `socket(AF_UNIX)`
  and `io_uring_setup` return `EACCES`, while `AF_VSOCK`/`AF_INET` are
  allowed. Build: `gcc -O2 -Wall -Wextra -o /tmp/05-seccomp-probe scripts/05-seccomp-probe.c`.
- `scripts/05-lineparser-fuzz.c` — **T9** AFL++ harness mirroring the guest
  supervisor's line assembler. Build: `afl-clang-fast -O2 -fsanitize=address
  -o /tmp/05-lineparser-fuzz scripts/05-lineparser-fuzz.c`.
- `scripts/05-install-agents.sh` — rebuilds all three guest binaries and
  installs them into `rootfs/05-rootfs.ext4` (needs sudo loop-mount).

## Test results obtained here

- **T8 (AF_UNIX / io_uring probe):** PASS — all four expectations held
  (`AF_UNIX` EACCES, `io_uring_setup` EACCES, `AF_VSOCK`/`AF_INET` allowed).
- **T9 (line-parser fuzz):** 55s `afl-fuzz` campaign under ASan, ~62% edge
  coverage, **0 crashes / 0 hangs**. ASan standalone replay also clean.
  Not exhaustive — a longer campaign is cheap and worth running.
- **SS1 default + kill:** PASS after all changes; receipts regenerated.

## Still open / not addressed here

- F8 (anchored verify) and F10 (jailer) — see table.
- T9 is a short campaign, not a soak. No soak fuzzing, no AFL on the host
  Python path, no `broker` source review (sibling repo), no kernel/
  Firecracker CVE review — all remain as the review's own residual-risk
  section states.
