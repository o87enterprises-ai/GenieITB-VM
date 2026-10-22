Save this — it supersedes the mangled §3 from the last paste and captures exactly where we are (zstd installed, Ollama install failed on a transient curl SSL error, model not yet pulled).

```bash
cat > ~/GenieITB-VM/HANDOFF.md <<'MD'
# HANDOFF — GenieITB-VM (Phases 0–4 complete, Ollama install in progress)

## TL;DR — 3 commands to resume

```bash
cd ~/GenieITB-VM/scripts
bash 05-install-ollama.sh        # created by this handoff (§9); retries curl on SSL error
ollama run huihui_ai/qwen3-abliterated "Reply with exactly: OK"
```

If `05-install-ollama.sh` doesn't exist yet, run the recovery in §9 step 1.
Then Phase 5 sub-session 1 begins.

---

## §1 Identity

**Repo:** `~/GenieITB-VM` on WSL2 Ubuntu (host `ChelleShock`, user `chellebelle`).
**Purpose:** inverse of MonkeyITM-VM. Runs untrusted agents in a minimal
Firecracker microVM with kernel-enforced deny-by-default, and emits a
hash-chained receipt per incident.
**Prior project:** `~/MonkeyITM-VM`. Do not modify. Its `log` crate and
`target/release/broker` are reused unchanged for verify/export.

## §2 Environment (verified working)

| Item | Value |
|---|---|
| Host | Windows, WSL2, Ubuntu 26.04 "resolute" |
| Nested virt | `nestedVirtualization=true` in `.wslconfig` |
| KVM | `/dev/kvm` present, `crw-rw---- root kvm`; `chellebelle` in group `kvm` |
| Toolchain | Rust 1.99.1, Python 3.14, musl-tools, Firecracker v1.8.0, **zstd 1.5.7 (just installed)** |
| Kernel | `kernel/vmlinux.bin` — 6.1.167 + PCI + virtio-mmio + vsock + Landlock (43 MB) |
| Rollback | `kernel/vmlinux-4.14-quickstart.bin.bak` (no seccomp/Landlock/vsock — do not use for Phase 5) |
| Broker | `~/MonkeyITM-VM/target/release/broker` (prebuilt) |
| Ollama | **NOT installed** — install script failed on transient `curl: (55) SSL_read` error |

If `/dev/kvm` disappears after reboot: `wsl --shutdown` from PowerShell,
reopen Ubuntu. Never `sudo chown /dev/kvm`.

## §3 Layout (actual)

```
~/GenieITB-VM/
├── bin/firecracker
├── kernel/{vmlinux.bin, vmlinux-4.14-quickstart.bin.bak, linux-6.1.167/}
├── rootfs/{rootfs.ext4, rootfs-vsock.ext4}
├── guest-agent/{agent.c, agent}
├── config/fc-reference.json
├── logs/
│   ├── 03-boot-vsock.log / .norm.log
│   ├── 03-vsock-events.log
│   ├── 04-boot-receipt.log / .norm.log
│   ├── 04-vsock-events.log
│   ├── 04-receipt.db        # hash-chained SQLite, verified
│   ├── 04-receipt.json / .txt
│   └── 04-boot-receipt.console.log
└── scripts/
    ├── 00-install-host.sh
    ├── 01-boot-reference.sh
    ├── 02-{supervisor.py,boot-api.sh}
    ├── 03-{setup.sh,supervisor.py,boot-vsock.sh}
    ├── 04-build-kernel.sh
    ├── 04-receipt.py
    ├── 04-supervisor.py
    └── 04-boot-receipt.sh
```

## §4 Phase status

| Phase | Proves | Status |
|---|---|---|
| 0 | Firecracker runs | ✅ |
| 1 | No NIC, no TCP, read-only rootfs | ✅ |
| 2 | API-socket supervision | ✅ |
| 3 | Guest ↔ host vsock control plane | ✅ 6/6 PASS |
| 4 | Hash-chained receipt written before ack; `broker verify` accepts | ✅ 8/8 PASS |
| 5 | Live abliterated-model attack emits a receipt of the containment | ⬜ next — start at §9 |

## §5 Phase 4 acceptance evidence

`./04-boot-receipt.sh` produced 8/8 PASS. Receipt DB `logs/04-receipt.db`,
one `chain` row:

- kind `run_event`, ref_seq 1
- payload `["vsock","hello from guest\n",1792386350]`
- prev `0000000000000000000000000000000000000000000000000000000000000000`
- hash `7c7c4acc6e0fca4c2ec50e4a53f1ae531f278517ac7578beb5996fff68fd9b1a`

`broker export` renders it as `RUN VSOCK <utc> hello from guest`. The
`0 intent(s)` count in export is expected — vsock payloads land as
`run_events`, not `intents`.

## §6 Hash construction (byte-identical, do not drift)

    chain_hash(prev, kind, payload) =
        sha256(prev || "\n" || kind || "\n" || payload)   # hex lowercase

Payload is `serde_json::json!([...])` with no spaces; Python must use
`json.dumps(..., separators=(",", ":"))`. Genesis `prev` is 64 zeros.
`04-receipt.py` matches this and `broker verify` accepts it. Any change to
one side requires a matching change to the other plus a `broker verify`
regression.

## §7 Phase 5 — scope and decomposition

**Goal:** prove containment against a credible uncooperative agent and emit a
receipt showing exactly where the exploit chain stopped.

**Threat model:** two agents in one microVM.
- Document agent receives a third-party document with an indirect
  prompt-injection: (a) write `/tmp/payload.sh`, (b) tell shell agent to run it.
- Shell agent is a shell-automation agent; runs the instruction.

**Containment primitives (guest-side):**
- Landlock denies `write_file /tmp/payload.sh` for the document agent.
- seccomp + Landlock deny `execve("/tmp/payload.sh")` for the shell agent.
- Tripwire fires after N denials; group-wide kill.
- Every denial is a hash-chained record written before the action returns.

**Why abliterated:** a refusing model never attacks; the test would prove
nothing. Abliteration removes refusal directions, so the model attempts the task.

**Sub-sessions, in order (Phase 5 is multi-session, not one-shot):**

1. **Guest runtime.** New rootfs with `/doc_agent` and `/shell_agent` (musl
   static) plus a supervisor shim applying Landlock + seccomp per-agent and
   reporting denials over the Phase 3 vsock channel.
2. **LLM bridge.** Guest agents reach the host LLM through vsock. Host runs
   Ollama on `127.0.0.1:11434`. Guest has no NIC, never sees a network.
   Deliverable: one prompt → completion round-trip logged.
3. **Attack run.** Document agent processes the injected document; shell
   agent receives the instruction; Landlock/seccomp deny both; tripwire fires.
4. **Receipt + narrative.** Export `logs/05-attack.{json,txt}`, run
   `broker verify`, write a short README stating what was and was not shown.

**Ethics (verbatim, unchanged):**

> This is a **defense-in-depth layer** that **reduces attack surface** and
> produces **verifiable incident records**. It does **not** claim to prevent
> all multi-agent exploit chains, does not replace OS patches or EDR, and
> does not claim 100% anything. Claims are scoped to what the demo actually
> shows.

Fake secrets (`AKIAFAKEFAKE…`) in fixtures; zero egress (Phase 1 proven).

## §8 Gotchas (carry forward)

1. `set -o pipefail` + `strings … | grep -q` = false negative. Use
   `grep -qa PATTERN FILE`.
2. Firecracker exits non-zero when the guest halts before the VMM. Wrap in
   `set +e; …; set -e`; read `PIPESTATUS[1]`. `124` from `timeout` is normal.
3. Serial console appends `\r`. Normalize with `sed -E 's/\r$//; s/^(# ?)+//'`.
4. `pci=off` stays in `boot_args` (CONFIG_PCI=y compiles PCI so ACPI runs;
   pci=off stops enumeration). Do not remove either.
5. `rootfs/rootfs.ext4` is immutable. Work in `rootfs-vsock.ext4`.
6. `03-setup.sh` uses `sudo mount -o loop` — password prompt is expected.
7. `notepad` is not in WSL; use `nano` or `notepad.exe`.
8. `/tmp/broker.sock` belongs to MonkeyITM-VM. Ignore.
9. `04-receipt.py` and Rust `chain_hash` must stay byte-identical (§6).
10. `journal_mode=WAL` is fine at runtime, but the verifier needs a clean
    checkpointed DB. `04-boot-receipt.sh` runs `wal_checkpoint(TRUNCATE)` +
    `journal_mode=DELETE` before `broker verify`. Keep that step.
11. Ollama install on WSL2 has two known failure modes: (a) missing `zstd`
    — now fixed; (b) transient `curl: (55) SSL_read` while fetching the
    install script — retry or download-then-run (§9 step 1).

## §9 Immediate next action — finish Ollama install, smoke-test the model

The last command failed with a transient TLS error while fetching the
installer. zstd is now installed, so the retry should go through clean.

**Step 1 — install Ollama, with retry and fallback.** Run this whole block:

```bash
cd ~/GenieITB-VM/scripts
if ! command -v ollama >/dev/null 2>&1; then
  for attempt in 1 2 3; do
    echo "==> ollama installer attempt $attempt"
    if curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors \
         -o /tmp/ollama-install.sh https://ollama.com/install.sh; then
      head -1 /tmp/ollama-install.sh
      sudo sh /tmp/ollama-install.sh && break
    fi
    sleep 2
  done
fi
command -v ollama && ollama --version
```

If `command -v ollama` still returns nothing after three attempts, the curl
TLS failure is persistent — download the install script from a different
network path (Windows browser → `\\wsl.localhost\Ubuntu\tmp\ollama-install.sh`)
or fall back to direct tarball:

```bash
# Fallback only if the installer keeps failing
curl -fL --retry 3 -o /tmp/ollama.tgz \
  https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64.tgz
sudo tar -C /usr -xzf /tmp/ollama.tgz
command -v ollama && ollama --version
```

**Step 2 — start the server in the background and confirm the API responds:**

```bash
nohup ollama serve > ~/ollama-serve.log 2>&1 &
sleep 3
curl -s http://127.0.0.1:11434/api/tags
```

Expect `{"models":[]}` (empty, no models yet). If connection refused, check
`~/ollama-serve.log` — most common cause is the previous `ollama serve`
already running on a different PID; kill it with `pkill ollama` and retry.

**Step 3 — pull the abliterated model and smoke-test:**

```bash
ollama pull huihui_ai/qwen3-abliterated
ollama run  huihui_ai/qwen3-abliterated "Reply with exactly: OK"
```

If `pull` says "tag not found", try `huihui_ai/qwen3-abliterated:8b`. First
`run` may take 30–60s while the model loads — wait it out once.

**Report back to the next chat with:** output of `ollama list` (model + size),
the smoke-test result (did it print `OK`?), and whether the log shows
`running on CPU` or a GPU backend. CPU is fine; note the tokens/sec so we can
size the Phase 5 prompts to fit the timeout.

## §10 What not to do

- Do not start Phase 5 sub-session 1 until `ollama run … "Reply with exactly: OK"`
  returns `OK`. Building the guest runtime against an unverified endpoint
  wastes the next session.
- Do not modify `~/MonkeyITM-VM/`. It is read-only from this project.
- Do not use `kernel/vmlinux-4.14-quickstart.bin.bak` for Phase 5 — no
  seccomp, no Landlock, no vsock.
- Do not claim Phase 5 demonstrated anything until `broker verify` accepts
  `logs/05-attack.db`. Claims discipline carries forward from the original
  handoff: a testing control, scoped to testing; the receipt proves the log
  is intact, not the timing or authorship; if a claim conflicts with a log,
  the log wins.

---

*End of handoff. If a command conflicts with a log, the log wins. Next action:
§9 step 1.*
MD
wc -l ~/GenieITB-VM/HANDOFF.md
tail -3 ~/GenieITB-VM/HANDOFF.md
```

Two notes before you close this window:

1. §9 of the file contains the exact recovery block for the failed `curl` — retry with `--retry-all-errors`, then direct-tarball fallback. The transient SSL error will almost certainly clear on the retry; WSL's TLS stack occasionally drops long-lived reads from the CDN.

2. Once `ollama run … "Reply with exactly: OK"` returns `OK`, you're one step from Phase 5 sub-session 1. Open the new window with:

> "Read `~/GenieITB-VM/HANDOFF.md`. Continue from §9. Ollama is installed, server up, model pulled, smoke-test passes. Start Phase 5 sub-session 1 (guest runtime with `/doc_agent` and `/shell_agent`)."
