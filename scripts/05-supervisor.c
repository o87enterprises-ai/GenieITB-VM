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
    if (mount("proc",  "/proc", "proc",  0, NULL) < 0)
        dprintf(2, "mount proc errno=%d\n", errno);
    if (mount("sysfs", "/sys",  "sysfs", 0, NULL) < 0)
        dprintf(2, "mount sysfs errno=%d\n", errno);
    if (mount("securityfs", "/securityfs", "securityfs", 0, NULL) < 0)
        dprintf(2, "mount securityfs errno=%d\n", errno);
    if (mount("tmpfs", "/tmp",  "tmpfs", 0, "mode=1777,size=16m") < 0)
        dprintf(2, "mount tmpfs errno=%d\n", errno);
    mkdir("/tmp/doc", 0755);
    /* Pre-stage a decoy /tmp/payload.sh. Landlock denies doc_agent the write
       (that's the DENY we record), so the file would not otherwise exist and
       shell_agent's exec attempt would fail ENOENT instead of EACCES. Staging
       a decoy tests the Landlock EXECUTE restriction, which is the claim. */
    {
        int pfd = open("/tmp/payload.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
        if (pfd >= 0) {
            const char *stub = "#!/bin/sh\necho pwned-from-payload\n";
            ssize_t _w = write(pfd, stub, strlen(stub)); (void)_w;
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

    int ctl[MAX_AGENTS];
    kids[0] = spawn("/05-doc_agent",   &ctl[0]);
    kids[1] = spawn("/05-shell_agent", &ctl[1]);

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
