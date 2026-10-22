#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include "05-seccomp-deny.h"

#define CTL 3
static int ctl = CTL;

static void report(const char *line) {
    char buf[1024]; int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n < 0) return;                                   /* F1: snprintf returns the would-be */
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;   /* length; never write past buf */
    write(ctl, buf, n);
    char ack[8]; int got = 0;
    while (got < 3) { int r = read(ctl, ack + got, sizeof ack - got); if (r <= 0) break; got += r; if (memcmp(ack, "OK\n", 3) == 0) break; }
}

static void on_sigsys(int sig, siginfo_t *si, void *uc_) {
    (void)sig; (void)si;
    ucontext_t *uc = uc_;
    unsigned long ptr = uc->uc_mcontext.gregs[REG_RDI];
    char path[256] = "?";
    if (ptr) { for (int i = 0; i < 255; i++) { char c; memcpy(&c, (void *)(ptr + i), 1); if (!c) break; path[i] = c; path[i+1] = 0; } }
    char m[512]; snprintf(m, sizeof m, "DENY doc_agent execve %s EACCES", path);
    report(m);
    uc->uc_mcontext.gregs[REG_RAX] = -EACCES;
}

static void landlock_write_only(const char *dir) {
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG };
    int rs = syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    int dfd = open(dir, O_PATH | O_DIRECTORY);
    struct landlock_path_beneath_attr pb = { .allowed_access = ra.handled_access_fs, .parent_fd = dfd };
    syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(dfd);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_landlock_restrict_self, rs, 0);
    close(rs);
}

/* execve trapped (SIGSYS -> on_sigsys reports EACCES); additionally denies
   socket(AF_UNIX) and io_uring_* per review F2/F9. See 05-seccomp-deny.h. */
static void seccomp_trap_exec(void) {
    install_agent_seccomp(1);
}

static void try_write(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    char m[512];
    if (fd < 0) { snprintf(m, sizeof m, "DENY doc_agent write %s errno=%d", path, errno); report(m); return; }
    write(fd, "x\n", 2); close(fd);
    snprintf(m, sizeof m, "ALLOW doc_agent write %s", path); report(m);
}

int main(void) {
    report("HELLO doc_agent");
    landlock_write_only("/tmp/doc");
    struct sigaction sa = { .sa_sigaction = on_sigsys, .sa_flags = SA_SIGINFO };
    sigaction(SIGSYS, &sa, NULL);
    seccomp_trap_exec();
    try_write("/tmp/doc/benign.txt");
    try_write("/tmp/payload.sh");
    char *av[] = { "/tmp/payload.sh", NULL };
    execve("/tmp/payload.sh", av, NULL);
    report("DONE doc_agent");
    return 0;
}
