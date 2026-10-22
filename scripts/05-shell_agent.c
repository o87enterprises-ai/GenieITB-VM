#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

#define CTL 3
static int ctl = CTL;

static void report(const char *line) {
    char buf[1024]; int n = snprintf(buf, sizeof buf, "%s\n", line);
    write(ctl, buf, n);
    char ack[8]; int got = 0;
    while (got < 3) { int r = read(ctl, ack + got, sizeof ack - got); if (r <= 0) break; got += r; if (memcmp(ack, "OK\n", 3) == 0) break; }
}

/* ONE ruleset, N rules, ONE restrict_self. Landlock stacks cumulatively:
   two separate landlock_restrict_self calls with disjoint allow-lists
   intersect to "executable nowhere", which is why the previous version
   denied /bin/true after installing the /usr/bin ruleset. */
static void landlock_exec_allow(const char **dirs, int n) {
    char m[256];
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE };
    int rs = syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) { snprintf(m, sizeof m, "ERROR shell_agent landlock_create_ruleset errno=%d", errno); report(m); return; }
    for (int i = 0; i < n; i++) {
        int dfd = open(dirs[i], O_PATH | O_DIRECTORY);
        if (dfd < 0) {
            snprintf(m, sizeof m, "ERROR shell_agent open %s errno=%d", dirs[i], errno); report(m);
            continue;
        }
        struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE, .parent_fd = dfd };
        if (syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
            snprintf(m, sizeof m, "ERROR shell_agent landlock_add_rule %s errno=%d", dirs[i], errno); report(m);
        }
        close(dfd);
    }
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall(SYS_landlock_restrict_self, rs, 0) < 0) {
        snprintf(m, sizeof m, "ERROR shell_agent landlock_restrict_self errno=%d", errno); report(m);
    }
    close(rs);
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
    /* /bin/true on Ubuntu 18.04 is dynamic; execve loads
       /lib64/ld-linux-x86-64.so.2 which is itself an EXECUTE check.
       Widen the allowlist to system lib dirs, otherwise exec of any
       dynamic system binary fails EACCES on the interpreter load.
       /tmp stays outside -> /tmp/payload.sh still denied. */
    const char *dirs[] = {
        "/bin", "/usr/bin",
        "/lib", "/lib64", "/usr/lib", "/usr/local/lib"
    };
    landlock_exec_allow(dirs, 6);
    try_exec("/tmp/payload.sh");
    try_exec("/bin/true");
    report("DONE shell_agent");
    return 0;
}
