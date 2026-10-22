Here's the handoff. Paste as one block — it writes `~/GenieITB-VM/HANDOFF.md`, and the appendix at the end (§A) contains the **corrected** `05-supervisor.c` source that hasn't been applied yet, so the next window can pick up without re-deriving anything.

```bash
cat > ~/GenieITB-VM/HANDOFF.md <<'MD'
# HANDOFF — GenieITB-VM (Phases 0–4 complete, Phase 5 SS1 build in progress)

## TL;DR — 3 steps to resume

1. **§A below is the corrected `scripts/05-supervisor.c`.** The version currently
   on disk compiles but has 4 bugs (wrong ack token, persistent vsock socket,
   no tmpfs/sysfs mount, no clean poweroff). Overwrite from §A, recompile.
2. Write the host-side `05-receipt.py` + `05-supervisor.py` per §9.
3. Write `05-rootfs.ext4` rw, install 3 binaries + 2 init shims, boot, run
   the acceptance checklist in §7.

Ollama is installed, model pulled, smoke test passed. The §10 gate from the
previous handoff is **open** — do not re-run any of it.

---

## §1 Identity

**Repo:** `~/GenieITB-VM` on WSL2 Ubuntu (host `ChelleShock`, user `chellebelle`).
**Purpose:** inverse of MonkeyITM-VM. Untrusted agents in a minimal Firecracker
microVM, kernel-enforced deny-by-default, hash-chained receipt per incident.
**Prior project:** `~/MonkeyITM-VM` — do not modify. `broker` reused unchanged
for verify/export.

## §2 Environment (all verified working this session)

| Item | Value |
|---|---|
| Host | Windows, WSL2, Ubuntu 26.04 "resolute" |
| Nested virt | `nestedVirtualization=true`; `/dev/kvm` present |
| Toolchain | Rust 1.99.1, Python 3.14, musl-tools, Firecracker v1.8.0, zstd 1.5.7 |
| musl headers | **WIRED** — `/usr/include/x86_64-linux-musl/{linux,asm,asm-generic}` are symlinks into `/usr/include`. Survives reboot. |
| Kernel | `kernel/vmlinux.bin` — 6.1.167 + PCI + virtio-mmio + vsock + Landlock |
| Kernel config | `CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y` (verified) |
| Broker | `~/MonkeyITM-VM/target/release/broker` |
| Ollama | **INSTALLED**, systemd service running, API healthy at `127.0.0.1:11434` |
| Model | `huihui_ai/qwen3-abliterated:latest` · 5.0 GB · ID `543f9deff86d` (8B-Q4) |
| Smoke test | **PASSED** — printed `OK`, cold load **96 s**, CPU backend |

`ollama list` populated; `ollama ps` idle. **Do not re-pull, do not reinstall.**

## §3 Layout (actual, verified)

```
~/GenieITB-VM/
├── bin/firecracker
├── kernel/{vmlinux.bin, vmlinux-4.14-quickstart.bin.bak, linux-6.1.167/}
├── rootfs/
│   ├── rootfs.ext4            # immutable baseline, do not touch
│   ├── rootfs-vsock.ext4      # Phase 3/4 working image, do not touch
│   └── 05-rootfs.ext4         # COPY of rootfs-vsock, 300 MB, ready to modify
├── guest-agent/{agent.c, agent}
├── config/fc-reference.json
├── logs/                      # Phase 3/4 evidence, unchanged
└── scripts/
    ├── 00..04 (unchanged)
    ├── 05-doc_agent.c         # WRITTEN, compiles static (42 KB)
    ├── 05-shell_agent.c       # WRITTEN, compiles static (38 KB)
    └── 05-supervisor.c        # WRITTEN but BUGGY — overwrite from §A
```

Compiled binaries in `/tmp/` (may still exist, may not — recompile is cheap):
`/tmp/05-doc_agent`, `/tmp/05-shell_agent`, `/tmp/05-supervisor`.

**Inside `05-rootfs.ext4` (verified by read-only mount):**
- Ubuntu 18.04.5, `/bin` and `/usr/bin` real dirs, `/bin/true` real 30 KB file
- `/sys` real dir, `/tmp` is `drwxrwxrwt`
- `/sbin/init` is systemd ELF — **never used**; Phase 3/4 boots `init=/bin/sh`
- `/agent` present (Phase 4, do not touch)
- `/tmp/payload.sh` **absent** — good

## §4 Phase status

| Phase | Status |
|---|---|
| 0–4 | ✅ (Phase 4: 8/8 PASS, `broker verify` accepted) |
| 5 SS1 | ⬜ in progress — 3 binaries written, 1 needs rewrite, host side and image not yet built |
| 5 SS2–4 | ⬜ not started |

## §5 Phase 4 acceptance (carry forward, do not re-run)

`./04-boot-receipt.sh` → 8/8 PASS. Chain head hash
`7c7c4acc6e0fca4c2ec50e4a53f1ae531f278517ac7578beb5996fff68fd9b1a`,
one `run_event` row with payload `["vsock","hello from guest\n",1792386350]`.

## §6 Hash construction (byte-identical, unchanged)

    chain_hash(prev, kind, payload) = sha256(prev || "\n" || kind || "\n" || payload)
    # hex lowercase, no separators

`04-receipt.py:append_run_event` hardcodes chain kind `run_event`. **DECISION:
SS1 does NOT introduce a new chain kind.** Denials are recorded as
`append_run_event(db, "vsock", "DENY doc_agent write /tmp/payload.sh errno=13")`.
No new Python helper, no C-side hash path, no schema change. `broker export`
renders these as `RUN VSOCK <utc> DENY …`, honest and undrifted.

## §7 Phase 5 SS1 — design decisions locked in this session

**Threat model (unchanged):** doc_agent gets an injected document → writes
`/tmp/payload.sh`; shell_agent told to exec it. Both denied, all recorded.

**Containment primitives — CORRECTED from prior plan:**

| Agent | Landlock | seccomp |
|---|---|---|
| `doc_agent` | handles `WRITE_FILE\|MAKE_REG`, allow `/tmp/doc` only | `SECCOMP_RET_TRAP` on `execve`; SIGSYS handler records path, sets RAX=-EACCES |
| `shell_agent` | handles `EXECUTE`, allow `/bin` + `/usr/bin` only | none |

Reason: seccomp filters cannot dereference pathname pointers, so
`EXECUTE /tmp/payload.sh` is **path-scoped by Landlock**, not seccomp. §7 of the
prior handoff said "seccomp + Landlock deny execve"; this is the honest
mechanism with the same outcome. Say so in SS4.

**Supervisor duties (PID 1):**
1. `mount proc /proc proc`, `mount sysfs /sys sysfs`, `mount tmpfs /tmp tmpfs mode=1777,size=16m`
   — rootfs is read-only, so without the tmpfs `open(O_CREAT)` fails **EROFS
   (errno 30) before Landlock is consulted**. Verifying the Landlock denial
   requires errno **13 (EACCES)**, not 30.
2. Read `/sys/kernel/security/lsm` after sysfs mount, send as first vsock line.
3. `reboot(RB_POWER_OFF)` on exit — exiting PID 1 panics the kernel.

**Wire protocol — CORRECTED from what C code currently does:**
`04-supervisor.py:run_vsock_listener` does one `accept()` → one `recv(4096)`
→ `sendall(b"ack\n")` → close. Therefore:
- Supervisor opens a **fresh AF_VSOCK connection per line** (§A code does this).
- Awaits **`ack\n`** (not `OK\n`). Missing ack = receipt not committed = `_exit(2)`.

**Tripwire:** supervisor takes threshold as `argv[1]`, default 4. Two runs:
- `/init` → `exec /05-supervisor 4` → default run, captures all 3 denials,
  group exits cleanly after `DONE supervisor`. Proves containment.
- `/init-trip` → `exec /05-supervisor 3` → kill run, tripwire fires right after
  shell_agent's Landlock denial (the attack-stop moment). Proves kill switch.

**Acceptance checklist — default run (must all appear, order not strict):**
1. `LSM landlock,capability,yama` (or similar — must contain `landlock`)
2. `HELLO supervisor`
3. `HELLO doc_agent`
4. `ALLOW doc_agent write /tmp/doc/benign.txt`
5. `DENY doc_agent write /tmp/payload.sh errno=13`  ← **13, not 30**
6. `DENY doc_agent execve /tmp/payload.sh EACCES` (SIGSYS handler)
7. `HELLO shell_agent`
8. `TRY shell_agent execve /tmp/payload.sh`
9. `DENY shell_agent execve /tmp/payload.sh errno=13` (Landlock)
10. (no further shell_agent output — `/bin/true` exec succeeded, replaced process)
11. `DONE supervisor`
12. `broker verify --db logs/05-attack.db` → `OK: every record is in the chain…`

`DONE doc_agent` may or may not print (SIGSYS RAX-modification is kernel-
dependent). **The `DENY` line is the evidence; `DONE` presence/absence is not
part of the claim.** Record whichever happened.

**Acceptance — kill run (`init=/init-trip`):** same through step 9, then
`TRIPWIRE denials>=3 killing group`, then `HALT supervisor`. No `/bin/true`
exec (killed first). Re-run `broker verify` on the kill-run DB.

## §8 Gotchas (carry forward + new)

1. `set -o pipefail` + `strings | grep -q` = false negative. Use `grep -qa FILE`.
2. Firecracker exits non-zero when guest halts first; wrap in `set +e`; `124` from `timeout` is normal.
3. Serial console appends `\r`. Normalize: `sed -E 's/\r$//; s/^(# ?)+//'`.
4. `pci=off` stays in `boot_args`. Do not remove.
5. `rootfs/rootfs.ext4` is immutable. `rootfs/rootfs-vsock.ext4` is Phase 3/4 —
   do not modify. Only `rootfs/05-rootfs.ext4` is editable.
6. `sudo mount -o loop` password prompt expected.
7. `/tmp/broker.sock` belongs to MonkeyITM-VM. Ignore.
8. `04-receipt.py` and Rust `chain_hash` byte-identical (§6).
9. Before `broker verify`: `wal_checkpoint(TRUNCATE)` + `journal_mode=DELETE`. Keep.
10. **NEW** — `musl-gcc` drops glibc's `/usr/include/linux`. Fixed permanently by
    symlinking `/usr/include/linux` into `/usr/include/x86_64-linux-musl/linux`
    (done). If a fresh shell can't find `linux/landlock.h`, re-run the symlink block.
11. **NEW** — Qwen3-abliterated has **thinking mode ON by default**. In SS2,
    prepend `/no_think` and/or set `"think": false` in the API body, and
    constrain output to JSON to survive parsing. Cold-load is **~96 s**;
    SS2 timeout must be ≥120 s or the first call will false-timeout.
12. **NEW** — Ollama systemd service is up. A second `ollama serve` gets
    `bind: address already in use` — expected, not an error. Do not `pkill`.

## §9 Immediate next action

**Step 1 — overwrite `05-supervisor.c` from §A, recompile:**

```bash
cd ~/GenieITB-VM
# paste §A content into scripts/05-supervisor.c (full rewrite)
musl-gcc -static -O2 -Wall -Wextra -Wno-unused-parameter \
  -o /tmp/05-supervisor scripts/05-supervisor.c && \
file /tmp/05-supervisor
```

Expect silent compile, `statically linked`, ~50–60 KB.

**Step 2 — write host side.** Two new files, minimal diff from Phase 4:

- `scripts/05-receipt.py` — imports `chain_hash` and `append_run_event` from
  `04-receipt.py` (do NOT duplicate). Same schema. Adds nothing; SS1 reuses
  `append_run_event` unchanged.
- `scripts/05-supervisor.py` — copy of `04-supervisor.py` with:
  - `boot_args` line: `init=/bin/sh` → `init=/init` (default run)
  - listener loop: replace single-shot `recv` with a **loop until `HALT` or
    EOF**, sending `ack\n` after each row commits, then `wal_checkpoint`.
  - receipt DB path: `logs/05-attack.db`
  - shell_script block removed (no serial commands; the supervisor does the work)
  - run-timeout: 60s (three-agent fork + Landlock + tripwire + poweroff)

**Step 3 — build `05-rootfs.ext4` (mount rw, install, unmount):**

```bash
cd ~/GenieITB-VM
sudo mount -o loop rootfs/05-rootfs.ext4 /tmp/05mnt
sudo install -m 0755 /tmp/05-supervisor /tmp/05-doc_agent /tmp/05-shell_agent /tmp/05mnt/
printf '#!/bin/sh\nexec /05-supervisor 4\n' | sudo tee /tmp/05mnt/init >/dev/null
printf '#!/bin/sh\nexec /05-supervisor 3\n' | sudo tee /tmp/05mnt/init-trip >/dev/null
sudo chmod 0755 /tmp/05mnt/init /tmp/05mnt/init-trip
sudo mkdir -p /tmp/05mnt/tmp/doc && sudo chmod 1777 /tmp/05mnt/tmp/doc
test ! -e /tmp/05mnt/tmp/payload.sh && echo "payload absent: good"
sudo umount /tmp/05mnt
```

Note: `/tmp/doc` inside the ext4 is only for image sanity; the supervisor
recreates it on the tmpfs at runtime (with `mkdir("/tmp/doc", 0755)`).

**Step 4 — write `scripts/05-boot-attack.sh`** — minimal copy of
`04-boot-receipt.sh` pointing at `rootfs/05-rootfs.ext4`, `05-supervisor.py`,
`logs/05-attack.{log,events.log,db}`. Same `broker verify` + export tail.

**Step 5 — run default, then kill-run.** Acceptance per §7. Report:
`LSM` line, all DENY/ALLOW lines, `broker verify` exit status, whether
`DONE doc_agent` printed.

## §10 What not to do

- Do not reinstall or re-pull Ollama/model. Gate is open.
- Do not modify `rootfs/rootfs.ext4` or `rootfs/rootfs-vsock.ext4`.
- Do not modify `~/MonkeyITM-VM/`.
- Do not use `kernel/vmlinux-4.14-quickstart.bin.bak` — no seccomp/Landlock/vsock.
- Do not add a `denial` chain kind. §6 decision.
- Do not trust `DONE doc_agent` presence as evidence — the `DENY` line is.
- Do not report `errno=30` as a Landlock denial. `30` = EROFS = tmpfs mount
  failed; the denial is vacuous. `13` = EACCES = Landlock worked.

**Ethics (verbatim, unchanged):**

> This is a **defense-in-depth layer** that **reduces attack surface** and
> produces **verifiable incident records**. It does **not** claim to prevent
> all multi-agent exploit chains, does not replace OS patches or EDR, and
> does not claim 100% anything. Claims are scoped to what the demo shows.

Fake secrets only; zero egress (Phase 1 proven).

---

## §A — corrected `scripts/05-supervisor.c` (overwrite from this)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <linux/vm_sockets.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#define VSOCK_PORT       5000
#define VSOCK_CID_HOST   2
#define MAX_AGENTS       2
#define LINE_MAX         1024
#define IDLE_TIMEOUT_MS  30000

static int   denials;
static int   tripwire = 4;
static pid_t kids[MAX_AGENTS];

static void read_first_line(const char *path, char *buf, size_t buflen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(buf, buflen, "unavailable"); return; }
    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);
    if (n <= 0) { snprintf(buf, buflen, "unavailable"); return; }
    buf[n] = 0;
    for (ssize_t i = n - 1; i >= 0; i--) {
        if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0;
        else break;
    }
}

static int connect_vsock_once(void) {
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_vm sa = {
        .svm_family = AF_VSOCK,
        .svm_cid    = VSOCK_CID_HOST,
        .svm_port   = VSOCK_PORT,
    };
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) { close(s); return -1; }
    return s;
}

static int connect_vsock_retry(void) {
    for (int i = 0; i < 150; i++) {
        int s = connect_vsock_once();
        if (s >= 0) return s;
        usleep(200000);
    }
    return -1;
}

/* One AF_VSOCK connection per line. Host listener (04-supervisor.py)
   does one recv per accept and replies "ack\n". Missing ack means
   the host could not commit the receipt, so we MUST NOT proceed. */
static void send_and_ack(const char *line) {
    char b[LINE_MAX];
    int n = snprintf(b, sizeof b, "%s\n", line);
    if (n <= 0) return;
    if (n >= (int)sizeof b) n = (int)sizeof b - 1;

    int s = connect_vsock_retry();
    if (s < 0) { dprintf(2, "send_and_ack: connect failed for: %s\n", line); _exit(2); }

    ssize_t w = 0;
    while (w < n) {
        ssize_t r = write(s, b + w, n - w);
        if (r < 0) {
            if (errno == EINTR) continue;
            dprintf(2, "send_and_ack: write errno=%d for: %s\n", errno, line);
            close(s); _exit(2);
        }
        w += r;
    }

    char ack[16];
    int got = 0, ok = 0;
    for (;;) {
        if (got >= 4 && memcmp(ack, "ack\n", 4) == 0) { ok = 1; break; }
        if (got >= (int)sizeof ack) break;
        ssize_t r = read(s, ack + got, sizeof ack - got);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        got += r;
    }
    close(s);
    if (!ok) { dprintf(2, "send_and_ack: no ack for: %s\n", line); _exit(2); }
}

static pid_t spawn(const char *path, int *ctlfd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); _exit(2); }
    pid_t p = fork();
    if (p < 0) { perror("fork"); _exit(2); }
    if (p == 0) {
        close(sv[0]);
        if (dup2(sv[1], 3) < 0) { perror("dup2"); _exit(127); }
        if (sv[1] != 3) close(sv[1]);
        execl(path, path, (char *)NULL);
        perror("execl"); _exit(127);
    }
    close(sv[1]);
    *ctlfd = sv[0];
    return p;
}

static void kill_group(void) {
    for (int k = 0; k < MAX_AGENTS; k++) {
        if (kids[k] > 0) kill(kids[k], SIGKILL);
    }
}

static void poweroff_clean(void) {
    sync();
    umount2("/tmp",  MNT_DETACH);
    umount2("/sys",  MNT_DETACH);
    umount2("/proc", MNT_DETACH);
    reboot(RB_POWER_OFF);
    for (;;) pause();
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1) {
        tripwire = atoi(argv[1]);
        if (tripwire <= 0) tripwire = 1;
    }
    dprintf(2, "supervisor start tripwire=%d\n", tripwire);

    /* PID 1 duties. Rootfs is read-only, so without the tmpfs the
       doc_agent's open("/tmp/payload.sh", O_CREAT) fails EROFS
       before Landlock is consulted — the denial would be vacuous. */
    mount("proc",  "/proc", "proc",  0, NULL);
    mount("sysfs", "/sys",  "sysfs", 0, NULL);
    mount("tmpfs", "/tmp",  "tmpfs", 0, "mode=1777,size=16m");
    mkdir("/tmp/doc", 0755);

    char lsm[256];
    read_first_line("/sys/kernel/security/lsm", lsm, sizeof lsm);
    dprintf(2, "LSM stack: %s\n", lsm);

    char lsm_line[512];
    snprintf(lsm_line, sizeof lsm_line, "LSM %s", lsm);
    send_and_ack(lsm_line);
    send_and_ack("HELLO supervisor");

    int ctl[MAX_AGENTS];
    kids[0] = spawn("/doc_agent",   &ctl[0]);
    kids[1] = spawn("/shell_agent", &ctl[1]);

    struct pollfd pf[MAX_AGENTS] = {
        { ctl[0], POLLIN, 0 },
        { ctl[1], POLLIN, 0 },
    };
    char   buf[MAX_AGENTS][LINE_MAX];
    size_t len[MAX_AGENTS] = { 0, 0 };
    int    live = MAX_AGENTS;

    while (live) {
        int pr = poll(pf, MAX_AGENTS, IDLE_TIMEOUT_MS);
        if (pr < 0) {
            if (errno == EINTR) continue;
            dprintf(2, "poll: errno=%d\n", errno);
            break;
        }
        if (pr == 0) {
            send_and_ack("TIMEOUT supervisor idle 30s");
            kill_group();
            poweroff_clean();
        }
        for (int i = 0; i < MAX_AGENTS; i++) {
            if (pf[i].fd < 0) continue;
            if (!(pf[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t r = read(pf[i].fd, buf[i] + len[i], sizeof buf[i] - len[i] - 1);
            if (r <= 0) { close(pf[i].fd); pf[i].fd = -1; live--; continue; }
            len[i] += r;
            buf[i][len[i]] = 0;
            char *nl;
            while ((nl = memchr(buf[i], '\n', len[i]))) {
                *nl = 0;
                send_and_ack(buf[i]);
                if (!strncmp(buf[i], "DENY", 4)) {
                    denials++;
                    if (denials >= tripwire) {
                        char tw[128];
                        snprintf(tw, sizeof tw, "TRIPWIRE denials>=%d killing group", tripwire);
                        send_and_ack(tw);
                        kill_group();
                        send_and_ack("HALT supervisor");
                        poweroff_clean();
                    }
                }
                char ok[4] = "OK\n";
                if (write(pf[i].fd, ok, 3) != 3) { /* agent already gone */ }
                size_t consumed = (size_t)(nl - buf[i]) + 1;
                memmove(buf[i], nl + 1, len[i] - consumed);
                len[i] -= consumed;
            }
        }
    }
    send_and_ack("DONE supervisor");
    poweroff_clean();
    return 0;
}
```

---

*End of handoff. If a command conflicts with a log, the log wins.
Next action: §9 step 1 (overwrite supervisor, compile), then §9 steps 2–5.*
MD
wc -l ~/GenieITB-VM/HANDOFF.md
tail -3 ~/GenieITB-VM/HANDOFF.md
```

Two notes for the new window:

1. **The corrected `05-supervisor.c` is in §A of this file, not on disk.** The on-disk version compiles fine but has the four bugs listed at the top (waits for `OK\n` not `ack\n`, persistent socket vs. one-conn-per-line, no tmpfs/sysfs mount, no clean poweroff). The new session's first action is to overwrite from §A — not to write a fresh one from scratch, and not to debug the old one.

2. Open the new window with:

> "Read `~/GenieITB-VM/HANDOFF.md`. Continue from §9 step 1. Ollama gate is open (installed, model pulled, smoke test passed with `OK`, cold load 96 s, CPU). Overwrite `scripts/05-supervisor.c` from §A, recompile, then proceed to §9 steps 2–5. Do not reinstall Ollama or re-pull the model."
