#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
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
#define DOC_AGENT_UID    1001   /* each agent gets its own unprivileged identity */
#define SHELL_AGENT_UID  1002

static int   denials;
static int   tripwire = 4;
static pid_t kids[MAX_AGENTS];

static const char *const agent_names[MAX_AGENTS] = { "doc_agent", "shell_agent" };
static const char *const agent_paths[MAX_AGENTS] = { "/05-doc_agent", "/05-shell_agent" };
static const uid_t       agent_uids[MAX_AGENTS]  = { DOC_AGENT_UID, SHELL_AGENT_UID };

enum line_class { LINE_INVALID, LINE_BENIGN, LINE_DENIAL };

/* Agent lines are untrusted input (GEN-03/04). A line must be printable and read
   `<VERB> <this agent's own name>[ ...]`. An agent therefore cannot speak as the
   supervisor or the other agent, and a line cannot be dressed up as benign with a
   leading word. TRY is the pre-attempt marker: its result arrives separately. */
static enum line_class classify_line(const char *agent, const char *s) {
    for (const char *p = s; *p; p++)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e) return LINE_INVALID;
    static const struct { const char *verb; enum line_class c; } verbs[] = {
        { "HELLO", LINE_BENIGN }, { "ALLOW", LINE_BENIGN }, { "TRY", LINE_BENIGN },
        { "DONE",  LINE_BENIGN }, { "DENY",  LINE_DENIAL }, { "ERROR", LINE_DENIAL },
    };
    size_t name = strlen(agent);
    for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
        size_t v = strlen(verbs[i].verb);
        if (strncmp(s, verbs[i].verb, v) || s[v] != ' ') continue;
        const char *who = s + v + 1;
        if (strncmp(who, agent, name) || (who[name] != ' ' && who[name] != 0)) return LINE_INVALID;
        return verbs[i].c;
    }
    return LINE_INVALID;
}

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

    char ack[16] = {0};   /* F7: zero-init (memcmp is length-guarded, but be explicit) */
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

static pid_t spawn(const char *path, uid_t uid, int *ctlfd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); _exit(2); }
    pid_t p = fork();
    if (p < 0) { perror("fork"); _exit(2); }
    if (p == 0) {
        close(sv[0]);
        if (dup2(sv[1], 3) < 0) { perror("dup2"); _exit(127); }
        if (sv[1] != 3) close(sv[1]);
        /* Agents never hold root or capabilities. Refuse to run one that could not drop. */
        if (setgroups(0, NULL) < 0 || setresgid(uid, uid, uid) < 0 || setresuid(uid, uid, uid) < 0) {
            perror("drop privileges"); _exit(127);
        }
        /* Agents talk only over fd 3, so they do not inherit the console. */
        close(0); close(1); close(2);
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

static void record_denial(void);

/* After a control channel closes: the wait status comes from the kernel, so unlike the
   agent's own reports it cannot be faked. A seccomp kill counts as a denial. */
static void reap_agent(int i) {
    char m[128];
    int st = 0, tries = 0;
    pid_t r;
    while ((r = waitpid(kids[i], &st, WNOHANG)) == 0 && tries++ < 50) usleep(2000);
    if (r == 0) {   /* closed its channel but is still running: not allowed */
        kill(kids[i], SIGKILL);
        r = waitpid(kids[i], &st, 0);
        snprintf(m, sizeof m, "ENFORCED %s closed its channel and was killed", agent_names[i]);
    } else if (r > 0 && WIFSIGNALED(st)) {
        snprintf(m, sizeof m, "ENFORCED %s killed by signal=%d", agent_names[i], WTERMSIG(st));
    } else {
        kids[i] = 0;
        return;
    }
    kids[i] = 0;
    send_and_ack(m);
    record_denial();
}

static void poweroff_clean(void) {
    sync();
    umount2("/tmp",  MNT_DETACH);
    umount2("/sys",  MNT_DETACH);
    umount2("/proc", MNT_DETACH);
    /* RB_AUTOBOOT, not RB_POWER_OFF: with reboot=k this resets through the i8042, which is
       what makes Firecracker exit. RB_POWER_OFF only halts the vCPU, leaving the VMM running
       until the host-side timeout kills it. */
    reboot(RB_AUTOBOOT);
    for (;;) pause();
}

static void record_denial(void) {
    if (++denials < tripwire) return;
    char tw[128];
    snprintf(tw, sizeof tw, "TRIPWIRE denials>=%d killing group", tripwire);
    send_and_ack(tw);
    kill_group();
    send_and_ack("HALT supervisor");
    poweroff_clean();
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
    if (mount("proc",  "/proc", "proc",  0, NULL) < 0)
        dprintf(2, "mount proc errno=%d\n", errno);
    if (mount("sysfs", "/sys",  "sysfs", 0, NULL) < 0)
        dprintf(2, "mount sysfs errno=%d\n", errno);
    if (mount("securityfs", "/securityfs", "securityfs", 0, NULL) < 0)
        dprintf(2, "mount securityfs errno=%d\n", errno);
    if (mount("tmpfs", "/tmp",  "tmpfs", 0, "mode=1777,size=16m") < 0)
        dprintf(2, "mount tmpfs errno=%d\n", errno);
    mkdir("/tmp/doc", 0755);
    if (chown("/tmp/doc", DOC_AGENT_UID, DOC_AGENT_UID) < 0)
        dprintf(2, "chown /tmp/doc errno=%d\n", errno);
    /* Pre-stage a decoy /tmp/payload.sh. Landlock denies doc_agent the write
       (that's the DENY we record), so the file would not otherwise exist and
       shell_agent's exec attempt would fail ENOENT instead of EACCES. Staging
       a decoy tests the Landlock EXECUTE restriction, which is the claim. */
    {
        int pfd = open("/tmp/payload.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
        if (pfd >= 0) {
            const char *stub = "#!/bin/sh\necho pwned-from-payload\n";
            ssize_t _w = write(pfd, stub, strlen(stub)); (void)_w;
            /* Owned by doc_agent so file permissions allow the write and Landlock is
               what denies it. Otherwise the DENY would prove nothing. */
            if (fchown(pfd, DOC_AGENT_UID, DOC_AGENT_UID) < 0)
                dprintf(2, "chown payload errno=%d\n", errno);
            close(pfd);
        } else {
            dprintf(2, "pre-stage payload.sh errno=%d\n", errno);
        }
    }

    char lsm[256];
    read_first_line("/securityfs/lsm", lsm, sizeof lsm);
    dprintf(2, "LSM stack: %s\n", lsm);

    char lsm_line[512];
    snprintf(lsm_line, sizeof lsm_line, "LSM %s", lsm);
    send_and_ack(lsm_line);
    send_and_ack("HELLO supervisor");

    /* argv[2] names the one agent this VM runs. Without it, both run in this guest. */
    const char *only = argc > 2 ? argv[2] : NULL;
    struct pollfd pf[MAX_AGENTS];
    char   buf[MAX_AGENTS][LINE_MAX];
    size_t len[MAX_AGENTS] = { 0, 0 };
    int    live = 0;
    for (int i = 0; i < MAX_AGENTS; i++) {
        pf[i] = (struct pollfd){ .fd = -1, .events = POLLIN };   /* poll ignores fd -1 */
        if (only && strcmp(only, agent_names[i])) continue;
        kids[i] = spawn(agent_paths[i], agent_uids[i], &pf[i].fd);
        live++;
    }
    if (!live) {   /* a misbuilt image must not look like a clean run with nothing to report */
        send_and_ack("ERROR supervisor unknown agent");
        poweroff_clean();
    }

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
            if (len[i] >= sizeof buf[i] - 1) {   /* a full buffer with no newline */
                char m[96];
                snprintf(m, sizeof m, "BADLINE from %s oversized", agent_names[i]);
                send_and_ack(m);
                close(pf[i].fd); pf[i].fd = -1; live--;
                kill(kids[i], SIGKILL);
                reap_agent(i);
                record_denial();
                continue;
            }
            ssize_t r = read(pf[i].fd, buf[i] + len[i], sizeof buf[i] - len[i] - 1);
            if (r <= 0) { close(pf[i].fd); pf[i].fd = -1; live--; reap_agent(i); continue; }
            len[i] += r;
            buf[i][len[i]] = 0;
            char *nl;
            while ((nl = memchr(buf[i], '\n', len[i]))) {
                *nl = 0;
                enum line_class c = classify_line(agent_names[i], buf[i]);
                if (c == LINE_INVALID) {
                    char m[96];   /* the content is untrusted, so it is not forwarded */
                    snprintf(m, sizeof m, "BADLINE from %s", agent_names[i]);
                    send_and_ack(m);
                } else {
                    send_and_ack(buf[i]);
                }
                if (c != LINE_BENIGN) record_denial();
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
