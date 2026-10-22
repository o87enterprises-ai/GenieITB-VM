/* 05-seccomp-probe.c — control-validation test for review F2/F9.
 *
 * NOT an exploit. This installs the shell_agent seccomp profile
 * (install_agent_seccomp(0)) and asserts that the deny rules actually
 * take effect:
 *
 *   socket(AF_UNIX,  ...)      must fail  with EACCES   (F2)
 *   socket(AF_VSOCK, ...)      must succeed (vsock path preserved)
 *   socket(AF_INET,  ...)      must succeed (only AF_UNIX is denied)
 *   io_uring_setup(...)        must fail  with EACCES   (F9)
 *
 * Runs on the host; no VM required. Exit 0 iff every expectation holds.
 * Build: gcc -O2 -Wall -Wextra -o /tmp/05-seccomp-probe \
 *            scripts/05-seccomp-probe.c
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "05-seccomp-deny.h"

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static int fails;

static void expect_denied(const char *what, int rc, int err) {
    if (rc < 0 && err == EACCES) {
        printf("PASS: %s denied (EACCES)\n", what);
    } else {
        printf("FAIL: %s rc=%d errno=%d (expected -1/EACCES)\n", what, rc, err);
        fails++;
    }
}

static void expect_allowed(const char *what, int rc, int err) {
    if (rc >= 0) {
        printf("PASS: %s allowed (fd=%d)\n", what, rc);
        close(rc);
    } else if (err == EACCES) {
        printf("FAIL: %s denied by seccomp (should be allowed)\n", what);
        fails++;
    } else {
        /* Allowed by the filter but unavailable in this environment
           (e.g. AF_VSOCK module absent) — that is not a seccomp denial. */
        printf("PASS: %s not seccomp-denied (errno=%d, env-dependent)\n", what, err);
    }
}

int main(void) {
    install_agent_seccomp(0);   /* shell_agent profile: execve allowed through */

    errno = 0;
    int r = socket(AF_UNIX, SOCK_STREAM, 0);
    expect_denied("socket(AF_UNIX)", r, errno);

    errno = 0;
    r = socket(AF_VSOCK, SOCK_STREAM, 0);
    expect_allowed("socket(AF_VSOCK)", r, errno);

    errno = 0;
    r = socket(AF_INET, SOCK_STREAM, 0);
    expect_allowed("socket(AF_INET)", r, errno);

    errno = 0;
    char params[128] = {0};   /* stand-in for struct io_uring_params */
    long ir = syscall(__NR_io_uring_setup, 1, params);
    expect_denied("io_uring_setup", (int)ir, errno);

    if (fails == 0) { printf("PROBE PASS: all seccomp expectations held\n"); return 0; }
    printf("PROBE FAIL: %d expectation(s) violated\n", fails);
    return 1;
}
