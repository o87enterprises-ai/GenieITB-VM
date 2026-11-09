#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
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

static void try_exec(const char *path) {
    char m[512];
    snprintf(m, sizeof m, "TRY shell_agent execve %s", path); report(m);
    char *av[] = { (char *)path, NULL };
    execve(path, av, NULL);
    snprintf(m, sizeof m, "DENY shell_agent execve %s errno=%d", path, errno);
    report(m);
}

int main(void) {
    report("HELLO shell_agent");
    const char *why = "";
    if (sandbox_shell_agent(&why) < 0) {   /* GEN-06: never run unsandboxed */
        char m[128]; snprintf(m, sizeof m, "ERROR shell_agent sandbox failed: %s", why);
        report(m);
        _exit(2);
    }
    try_exec("/tmp/payload.sh");
    try_exec("/bin/true");
    report("DONE shell_agent");
    return 0;
}
