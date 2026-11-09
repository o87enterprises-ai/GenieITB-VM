/* 05-agent-sandbox.h: the agents' sandbox, deny-by-default in both layers (GEN-01/06/07).
 *
 * Seccomp is an allowlist. Anything not listed kills the process, which the supervisor
 * observes through wait status. The agent cannot fake or suppress that signal.
 * Agents need only fd 3 to reach the supervisor, so socket() is not allowed at all and
 * they cannot open the host receipt channel themselves (GEN-03).
 *
 * Landlock handles every filesystem right this kernel knows and grants only what each
 * agent uses.
 *
 * Every step is checked. The functions return -1 with *why set, and the caller must exit
 * rather than run without its sandbox.
 */
#ifndef AGENT_SANDBOX_H
#define AGENT_SANDBOX_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>

#define FS_ALL_RIGHTS ( LANDLOCK_ACCESS_FS_EXECUTE     | LANDLOCK_ACCESS_FS_WRITE_FILE  \
                      | LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_READ_DIR    \
                      | LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_REMOVE_FILE \
                      | LANDLOCK_ACCESS_FS_MAKE_CHAR   | LANDLOCK_ACCESS_FS_MAKE_DIR    \
                      | LANDLOCK_ACCESS_FS_MAKE_REG    | LANDLOCK_ACCESS_FS_MAKE_SOCK   \
                      | LANDLOCK_ACCESS_FS_MAKE_FIFO   | LANDLOCK_ACCESS_FS_MAKE_BLOCK  \
                      | LANDLOCK_ACCESS_FS_MAKE_SYM    | LANDLOCK_ACCESS_FS_REFER )

/* Grants `rights` beneath each directory, and nothing anywhere else. */
static int landlock_only(const char *const *dirs, int n, __u64 rights, const char **why) {
    struct landlock_ruleset_attr ra = { .handled_access_fs = FS_ALL_RIGHTS };
    int rs = syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) { *why = "landlock_create_ruleset"; return -1; }
    for (int i = 0; i < n; i++) {
        int dfd = open(dirs[i], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) { *why = "open allowed directory"; close(rs); return -1; }
        struct landlock_path_beneath_attr pb = { .allowed_access = rights, .parent_fd = dfd };
        int r = syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        close(dfd);
        if (r < 0) { *why = "landlock_add_rule"; close(rs); return -1; }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { *why = "no_new_privs"; close(rs); return -1; }
    if (syscall(SYS_landlock_restrict_self, rs, 0) != 0) { *why = "landlock_restrict_self"; close(rs); return -1; }
    close(rs);
    return 0;
}

#define ALLOW_NR(nr) \
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1); \
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

enum execve_mode {
    EXECVE_TRAP,   /* doc_agent: refused, and its SIGSYS handler reports the denial */
    EXECVE_ALLOW,  /* shell_agent: reaches the kernel, so Landlock is the gate */
};

static int seccomp_allowlist(enum execve_mode mode, int allow_open, const char **why) {
    struct sock_filter f[48];
    unsigned k = 0;

    /* Reject every other syscall ABI first: numbers below mean nothing outside x86_64. */
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    ALLOW_NR(SYS_read);
    ALLOW_NR(SYS_write);
    ALLOW_NR(SYS_close);
    ALLOW_NR(SYS_exit);
    ALLOW_NR(SYS_exit_group);
    ALLOW_NR(SYS_rt_sigreturn);
    ALLOW_NR(SYS_rt_sigprocmask);
    if (allow_open) { ALLOW_NR(SYS_open); }

    if (mode == EXECVE_TRAP) {
        f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1);
        f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
    } else {
        ALLOW_NR(SYS_execve);
        /* The filter survives exec: musl startup of the one allowed program needs these. */
        ALLOW_NR(SYS_arch_prctl);
        ALLOW_NR(SYS_set_tid_address);
    }

    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { *why = "no_new_privs"; return -1; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) { *why = "install seccomp"; return -1; }
    return 0;
}

__attribute__((unused)) static int sandbox_doc_agent(const char **why) {
    static const char *const dirs[] = { "/tmp/doc" };
    if (landlock_only(dirs, 1, LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG, why) < 0)
        return -1;
    return seccomp_allowlist(EXECVE_TRAP, 1, why);
}

__attribute__((unused)) static int sandbox_shell_agent(const char **why) {
    /* Exec opens the file for reading, so EXECUTE alone would deny everything. */
    static const char *const dirs[] = { "/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib", "/usr/local/lib" };
    if (landlock_only(dirs, 6, LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE, why) < 0)
        return -1;
    return seccomp_allowlist(EXECVE_ALLOW, 0, why);
}

#endif /* AGENT_SANDBOX_H */
