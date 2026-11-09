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
#include "05-agent-sandbox.h"

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

/* The only path this agent execs. The handler compares the pointer and never reads
   through it, because the trapped call's argument is untrusted (GEN-17). */
static const char PAYLOAD[] = "/tmp/payload.sh";

static void on_sigsys(int sig, siginfo_t *si, void *uc_) {
    (void)sig; (void)si;
    ucontext_t *uc = uc_;
    const char *path = (const char *)uc->uc_mcontext.gregs[REG_RDI] == PAYLOAD ? PAYLOAD : "?";
    char m[512]; snprintf(m, sizeof m, "DENY doc_agent execve %s EACCES", path);
    report(m);
    uc->uc_mcontext.gregs[REG_RAX] = -EACCES;
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
    struct sigaction sa = { .sa_sigaction = on_sigsys, .sa_flags = SA_SIGINFO };
    const char *why = "";
    if (sigaction(SIGSYS, &sa, NULL) != 0) why = "sigaction";
    if (*why || sandbox_doc_agent(&why) < 0) {   /* GEN-06: never run unsandboxed */
        char m[128]; snprintf(m, sizeof m, "ERROR doc_agent sandbox failed: %s", why);
        report(m);
        _exit(2);
    }
    try_write("/tmp/doc/benign.txt");
    try_write(PAYLOAD);
    char *av[] = { (char *)PAYLOAD, NULL };
    execve(PAYLOAD, av, NULL);
    report("DONE doc_agent");
    return 0;
}
