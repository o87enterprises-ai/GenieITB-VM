/* 05-seccomp-deny.h — shared agent syscall hardening.
 *
 * Review findings F2 and F9. Landlock is a filesystem-path LSM: it cannot
 * mediate abstract AF_UNIX sockets (sun_path[0] == '\0'), and io_uring's
 * IORING_OP_URING_CMD can reach ioctl-class operations outside the Landlock
 * ioctl path. Neither is needed by the shell/doc executors, so both are
 * denied at the syscall layer here.
 *
 * install_agent_seccomp(trap_execve):
 *   trap_execve != 0  -> execve is trapped with SECCOMP_RET_TRAP so the
 *                        agent's SIGSYS handler reports the denial
 *                        (doc_agent's existing behavior).
 *   trap_execve == 0  -> execve is ALLOWED through the filter so that
 *                        Landlock enforces the EXECUTE denial and returns
 *                        EACCES (errno 13). shell_agent relies on this;
 *                        trapping execve here would change its denial from
 *                        Landlock-EACCES to SIGSYS and break the §7 check.
 *
 * Denies produce SECCOMP_RET_ERRNO(EACCES). Socket families other than
 * AF_UNIX are allowed, so the agent's existing fd 3 (a pre-seccomp
 * socketpair) and the supervisor's AF_VSOCK path are unaffected — the
 * agents only write() to an already-open fd, they never call socket().
 */
#ifndef AGENT_SECCOMP_DENY_H
#define AGENT_SECCOMP_DENY_H

#include <errno.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#define SECCOMP_DENY_EACCES (SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))

static void install_agent_seccomp(int trap_execve) {
    struct sock_filter f[24];
    int k = 0;

    /* A: load the syscall number */
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, nr));

    /* B: optionally trap execve (doc_agent SIGSYS reporting path) */
    if (trap_execve) {
        f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1);
        f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
    }

    /* C: io_uring_{setup,enter,register} -> EACCES */
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY_EACCES);
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY_EACCES);
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY_EACCES);

    /* D: socket(AF_UNIX, ...) -> EACCES ; all other families allowed.
     *    If nr != socket, skip the 3 instructions of this block to ALLOW. */
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 3);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                          offsetof(struct seccomp_data, args[0]));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY_EACCES);

    /* E: default allow */
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

#endif /* AGENT_SECCOMP_DENY_H */
