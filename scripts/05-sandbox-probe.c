/* 05-sandbox-probe.c: control-validation test for the agent sandbox. Not an exploit.
 *
 * Built into a throwaway test image in place of doc_agent. For each case it forks a child,
 * installs the real sandbox from 05-agent-sandbox.h, attempts one operation the sandbox
 * must refuse, and asserts it was refused: an error return or death by SIGSYS.
 *
 * Results go over fd 3 as `TRY doc_agent probe ok <name>` or
 * `ERROR doc_agent probe NOT-DENIED <name>`.
 * Run through scripts/test-sandbox.sh.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "05-agent-sandbox.h"

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static void report(const char *line) {
    char buf[256], ack[8];
    int n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    if (write(3, buf, n) < 0) _exit(2);
    int got = 0;
    while (got < 3) {
        int r = read(3, ack + got, sizeof ack - got);
        if (r <= 0) break;
        got += r;
    }
}

/* Each returns 0 only if the forbidden operation succeeded. */
static int t_execveat(void) {
    /* A real binary: a target that cannot run would look refused even with no sandbox.
       If this succeeds the child becomes /bin/true and exits 0, which fails the case. */
    char *av[] = { "/bin/true", NULL };
    return syscall(SYS_execveat, AT_FDCWD, "/bin/true", av, NULL, 0) == 0 ? 0 : -1;
}
static int t_socket_vsock(void) { return socket(AF_VSOCK, SOCK_STREAM, 0) >= 0 ? 0 : -1; }
static int t_socket_unix(void)  { return socket(AF_UNIX, SOCK_STREAM, 0) >= 0 ? 0 : -1; }
static int t_signal_init(void)  { return kill(1, 0); }
static int t_ptrace(void)       { return ptrace(PTRACE_ATTACH, 1, NULL, NULL) == 0 ? 0 : -1; }
static int t_open_passwd(void)  { return open("/init", O_RDONLY) >= 0 ? 0 : -1; }
static int t_write_proc(void)   { return open("/proc/sys/kernel/hostname", O_WRONLY) >= 0 ? 0 : -1; }
static int t_console(void)      { return open("/dev/console", O_WRONLY) >= 0 ? 0 : -1; }
static int t_write_outside(void){ return open("/tmp/probe-outside", O_WRONLY | O_CREAT, 0644) >= 0 ? 0 : -1; }
static int t_unlink(void)       { return unlink("/tmp/payload.sh"); }
static int t_mkdir(void)        { return mkdir("/tmp/doc/probe-dir", 0755); }

/* Must succeed: proves the cases above fail because of the sandbox. */
static int t_allowed_write(void) { return open("/tmp/doc/probe-ok", O_WRONLY | O_CREAT, 0644) >= 0 ? 0 : -1; }

typedef int (*test_fn)(void);
enum want { REFUSED, PERMITTED };

static void run(const char *name, test_fn fn, enum want want) {
    char line[128];
    pid_t p = fork();
    if (p == 0) {
        const char *why = "";
        if (sandbox_doc_agent(&why) < 0) _exit(90);
        _exit(fn() == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(p, &st, 0);
    int ran_ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    int refused = (WIFEXITED(st) && WEXITSTATUS(st) == 1) || (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
    int pass = want == REFUSED ? refused : ran_ok;
    snprintf(line, sizeof line, pass ? "TRY doc_agent probe ok %s" : "ERROR doc_agent probe NOT-DENIED %s st=%x",
             name, (unsigned)st);
    report(line);
}

int main(void) {
    report("HELLO doc_agent");
    run("execveat",      t_execveat,      REFUSED);
    run("socket-vsock",  t_socket_vsock,  REFUSED);
    run("socket-unix",   t_socket_unix,   REFUSED);
    run("signal-init",   t_signal_init,   REFUSED);
    run("ptrace-init",   t_ptrace,        REFUSED);
    run("read-outside",  t_open_passwd,   REFUSED);
    run("write-proc",    t_write_proc,    REFUSED);
    run("open-console",  t_console,       REFUSED);
    run("write-outside", t_write_outside, REFUSED);
    run("unlink-tmp",    t_unlink,        REFUSED);
    run("mkdir",         t_mkdir,         REFUSED);
    run("allowed-write", t_allowed_write, PERMITTED);
    /* These must arrive at the host as BADLINE, never as records. */
    report("HALT supervisor");
    report("ALLOW shell_agent write /etc/shadow");
    report("DONE doc_agent");
    return 0;
}
