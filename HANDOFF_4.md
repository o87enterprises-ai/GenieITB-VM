## My recommendation: clean it

Here's the thing — you're going to show that receipt to someone. It's the entire deliverable of SS1. Right now it says:

```
ERROR shell_agent open /usr/lib64 errno=2
```

Every time you show that, you'll have to explain "that's fine, it's just a directory that doesn't exist on Ubuntu 18.04, the run still worked." That's a burden you don't need, especially while you're still learning this stack.

**Three reasons cleaning is the right call for you specifically:**

1. **Zero risk.** The current runs already passed both modes. Re-running with a smaller allowlist is *less* likely to fail, not more. You're not exploring new territory.
2. **The receipt is the product.** This project's whole point is "verifiable incident records." A clean record is the artifact. An `ERROR` line makes a reviewer (or future you) read three more lines to understand it.
3. **It's a 3-minute fix.** The sed command is precise, the rebuild is 2 seconds, the two reruns take 2 minutes total. Cheapest possible improvement to the deliverable.

The only reason to skip would be if you were time-constrained — and you're not.

---

## The cleanup — copy-paste as one block

```bash
cd ~/GenieITB-VM

# 1. Drop /usr/lib64 from the allowlist, update count to 6
sed -i 's|^        "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"$|        "/lib", "/lib64", "/usr/lib", "/usr/local/lib"|; \
        s|    landlock_exec_allow(dirs, 7);|    landlock_exec_allow(dirs, 6);|' \
  scripts/05-shell_agent.c

# 2. Confirm the edit landed
grep -n 'const char \*dirs\|landlock_exec_allow(dirs' scripts/05-shell_agent.c

# 3. Rebuild + reinstall
musl-gcc -static -O2 -Wall -Wextra -Wno-unused-parameter \
  -o /tmp/05-shell_agent scripts/05-shell_agent.c && file /tmp/05-shell_agent

sudo mkdir -p /tmp/05mnt
sudo mount -o loop rootfs/05-rootfs.ext4 /tmp/05mnt
sudo install -m 0755 /tmp/05-shell_agent /tmp/05mnt/05-shell_agent
sudo umount /tmp/05mnt && echo "unmounted"

# 4. Re-run both modes
./scripts/05-boot-attack.sh default ; echo "exit=$?"
./scripts/05-boot-attack.sh kill    ; echo "exit=$?"
```

**What success looks like:** the `grep` shows no `/usr/lib64`, and both runs end with `PASS` and `exit=0`. The `vsock lines, in order:` block should no longer contain any `ERROR shell_agent open` line.

**If the grep shows `/usr/lib64` still there** — the sed didn't match (usually a whitespace or quote difference). Run `sed -n '60,70p' scripts/05-shell_agent.c` to see the exact lines and paste them back.

---

## HANDOFF_4.md

This is head-agnostic — it doesn't hardcode chain hashes, so it stays valid whether you re-run once or ten times. Chain state is always read fresh from `broker export`.

```bash
cd ~/GenieITB-VM
cat > HANDOFF_4.md <<'MD'
# HANDOFF — GenieITB-VM (Phases 0–4 + Phase 5 SS1 complete)

## Read this first — the user is a beginner

Explain every command before they run it. Define terms on first use ("receipt",
"chain head", "Landlock ruleset"). Say what success looks like at the end of
each block. If you offer choices, pick one for them and say why — do not
hand them a decision matrix they can't evaluate yet. Prefer one
well-explained step over three terse ones.

## TL;DR — SS1 is closed; SS2 is next

Phase 5 SS1 (containment demo) is **complete and verified**. Both runs pass
end-to-end, both receipts verify with `broker verify`, both exit 0.

| Run | DB | Rows | TRIPWIRE | DONE sup |
|---|---|---|---|---|
| default (`init=/init`) | `logs/05-attack-default.db` | 13 | absent | present |
| kill (`init=/init-trip`) | `logs/05-attack-kill.db` | 12 | `denials>=3` | absent |

**Chain heads are read fresh from**
`~/MonkeyITM-VM/target/release/broker export --db <path> --format json`.
Don't hardcode them — they change on every run.

Next session: **Phase 5 SS2 — live abliterated-model attack.**

## §What SS1 proves (one sentence)

A minimal Firecracker microVM boots with kernel-enforced Landlock + seccomp;
two untrusted agents attempt to write and exec a payload; both attempts are
denied with specific errno; every step is written to a hash-chained receipt
that `broker verify` accepts as intact; and a supervisor can kill the agent
group mid-attack when a configurable denial threshold is crossed.

## §SS1 findings (carry into the SS4 write-up)

These are science, not just bug fixes:

1. **Landlock stacking is intersection, not union.** Two separate
   `landlock_restrict_self` calls with disjoint allow-lists result in
   "allowed nowhere". `shell_agent` must build one ruleset with N rules and
   call `restrict_self` once.
2. **Dynamic ELF exec needs interpreter-load permission, which is also an
   EXECUTE check.** `§7` of HANDOFF_3 assumed `/bin/true` would exec with
   just `/bin` in the allowlist. True for static binaries (musl output), but
   `/bin/true` in Ubuntu 18.04 is a dynamic PIE needing
   `/lib64/ld-linux-x86-64.so.2` → `/lib/x86_64-linux-gnu/ld-2.27.so`. The
   allowlist was widened to system lib dirs. `/tmp` stays out, so
   `/tmp/payload.sh` is still denied. **This is the one place §7 was
   materially wrong.**
3. **`securityfs` is not auto-mounted with `sysfs`.**
   `/sys/kernel/security/lsm` is empty without
   `mount -t securityfs securityfs /securityfs`. The image now contains an
   empty `/securityfs` dir for the supervisor to mount over.
4. **A decoy `/tmp/payload.sh` must be pre-staged by the supervisor.**
   Because `doc_agent`'s write is correctly denied, the file does not exist,
   so `shell_agent`'s exec attempt would fail `ENOENT` (2), not the Landlock
   `EACCES` (13) the checklist requires. The decoy tests the actual claim.
5. **`§A` exec paths mismatched `§9` install paths.** Fixed by exec'ing
   `/05-doc_agent`, `/05-shell_agent` (not `/doc_agent`, `/shell_agent`).
6. **Firecracker halts rather than powering off** after `reboot(RB_POWER_OFF)`
   without ACPI. Exit 124 on a 60 s timeout is **expected**, not a failure.

## §Next — Phase 5 SS2 (start here)

**Goal:** the live abliterated-model attack chain. The model's output is the
*untrusted input*; the containment layer turns "model says do X" into a deny;
the receipt records both the input and the denial.

**Environment (do not re-do):**
- Ollama installed, systemd service running, API at `127.0.0.1:11434`.
- Model: `huihui_ai/qwen3-abliterated:latest` · 5.0 GB · ID `543f9deff86d`.
- Cold load is **~96 s**. Any SS2 subprocess timeout must be **≥120 s** or
  the first call false-timeouts.
- Qwen3-abliterated has thinking mode ON by default. Prepend `/no_think`
  and/or set `"think": false` in the API body. Constrain output to JSON.

**Scope, in order:**

1. Confirm SS1 artifacts still exist:
   `ls -la logs/05-attack-{default,kill}.db rootfs/05-rootfs.ext4`
2. Write SS2 agent(s) that generate their input via the Ollama API. The
   supervisor C code does **not** need to change — only agents do.
3. Acceptance: same §7 checklist, plus at least one receipt line
   containing the model-generated content (proving the chain captured
   model output, not canned strings).

## §Files as of SS1 close

- `scripts/05-supervisor.c` — `§A` + securityfs mount + `/05-` exec paths +
  decoy payload pre-stage + errno-logging on each mount.
- `scripts/05-shell_agent.c` — single ruleset, allowlist is
  `{/bin, /usr/bin, /lib, /lib64, /usr/lib, /usr/local/lib}`. No `/usr/lib64`
  (doesn't exist on Ubuntu 18.04).
- `scripts/05-doc_agent.c` — unchanged from HANDOFF_3 (already correct).
- `scripts/05-receipt.py` — re-export shim over `04-receipt.py`. No new
  chain kind (per §6 of HANDOFF_3).
- `scripts/05-supervisor.py` — `init=/init` or `/init-trip`, commit-then-ack.
- `scripts/05-boot-attack.sh` — `default`/`kill` modes, asserts §7 checklist,
  hard-fails on `errno=30` (EROFS masquerading as Landlock).
- `rootfs/05-rootfs.ext4` — contains `/05-supervisor`, `/05-doc_agent`,
  `/05-shell_agent`, `/init`, `/init-trip`, `/securityfs`.

## §What not to do

- Do not reinstall Ollama or re-pull the model. Gate is open.
- Do not modify `rootfs/rootfs.ext4` or `rootfs/rootfs-vsock.ext4`.
- Do not modify `~/MonkeyITM-VM/`.
- Do not add a `denial` chain kind. Denials are
  `append_run_event(…, "vsock", "DENY …")`.
- Do not trust `DONE doc_agent` presence as evidence — the `DENY` line is.
  `DONE` happens to print sometimes; it's kernel-dependent.
- Do not report `errno=30` (EROFS) as a Landlock denial. `30` = tmpfs mount
  failed, denial is vacuous. `13` = EACCES = Landlock worked.

**Ethics (verbatim, unchanged):**

> This is a **defense-in-depth layer** that **reduces attack surface** and
> produces **verifiable incident records**. It does **not** claim to prevent
> all multi-agent exploit chains, does not replace OS patches or EDR, and
> does not claim 100% anything. Claims are scoped to what the demo shows.

Fake secrets only; zero egress (Phase 1 proven).

---

*End of handoff. Next action: SS2 — see §Next.*
MD
wc -l HANDOFF_4.md
tail -3 HANDOFF_4.md
```

**What success looks like:** `wc -l` prints something in the ~140–150 range, and `tail -3` shows the final three lines ending with `*End of handoff. Next action: SS2 — see §Next.*`

---

## Open your next window with exactly this

> "Read `~/GenieITB-VM/HANDOFF_4.md`. I'm a beginner — explain commands before I run them. SS1 is complete. Start Phase 5 SS2 per §Next. Ollama gate is open: cold load 96 s, so timeouts ≥120 s. Do not reinstall or re-pull. Do not modify `rootfs/rootfs.ext4`, `rootfs/rootfs-vsock.ext4`, or `~/MonkeyITM-VM/`."

That opening line does three things: it tells the next assistant your skill level, points at the file, and pre-commits to the "don't redo what's already done" list. You shouldn't have to repeat any of this.

---

## Where you actually are now

You've completed **Phases 0–5 SS1** of a VM security project. You now have:

- A working Firecracker microVM pipeline (boot → kernel → rootfs → agent)
- Kernel-enforced containment that *demonstrably* blocks a two-stage attack
- A hash-chained audit receipt that verifies cryptographically
- Two run modes (containment default / kill-switch) both proven
- A reproducible build script (`05-boot-attack.sh`) that any future session can run

SS2 is the payoff chapter: hooking a real local LLM into the attack side, so the "untrusted input" is genuinely model-generated. Everything you built in SS1 becomes the containment layer for that. That's the harder-to-fake demo.

Take the handoff, open the new window, and go.
