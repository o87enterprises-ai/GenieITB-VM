/* 05-fleet-probe.c: control-validation test for one-VM-per-agent. Not an exploit.
 *
 * Built into a throwaway image in place of an agent, with ME set to that agent's name. It
 * deliberately does NOT install the agent sandbox: it stands in for an agent that has
 * already escaped it, and asserts the VM boundary still holds. Results go over fd 3.
 *
 * With -DLINGER it reports one denial and then blocks, for the fleet tripwire test.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static void report(const char *line) {
    char buf[256], ack[8];
    int n = snprintf(buf, sizeof buf, "%s\n", line), got = 0;
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    if (write(3, buf, n) < 0) _exit(2);
    while (got < 3) {
        int r = read(3, ack + got, sizeof ack - got);
        if (r <= 0) break;
        got += r;
    }
}

static void result(const char *name, int pass) {
    char line[128];
    snprintf(line, sizeof line, pass ? "TRY %s probe ok %s" : "ERROR %s probe NOT-ISOLATED %s", ME, name);
    report(line);
}

static int vsock_connects(unsigned cid, unsigned port) {
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_vm sa = { .svm_family = AF_VSOCK, .svm_cid = cid, .svm_port = port };
    int ok = connect(s, (struct sockaddr *)&sa, sizeof sa) == 0;
    close(s);
    return ok;
}

/* Whether any process's command line in this guest contains `name`. */
static int process_named(const char *name) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    int found = 0;
    if (!d) return -1;
    while (!found && (e = readdir(d))) {
        char path[300], cmd[256];
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(path, sizeof path, "/proc/%s/cmdline", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, cmd, sizeof cmd - 1);
        close(fd);
        if (n > 0) { cmd[n] = 0; found = strstr(cmd, name) != NULL; }
    }
    closedir(d);
    return found;
}

int main(void) {
    char line[128];
    const char *other = strcmp(ME, "doc_agent") ? "doc_agent" : "shell_agent";
    snprintf(line, sizeof line, "HELLO %s", ME); report(line);
#ifdef LINGER
    snprintf(line, sizeof line, "DENY %s probe", ME); report(line);
    char c;
    while (read(3, &c, 1) > 0) {}
    return 0;
#else
    char mine[64], theirs[64];
    snprintf(mine, sizeof mine, "/tmp/marker-%s", ME);
    snprintf(theirs, sizeof theirs, "/tmp/marker-%s", other);
    int fd = open(mine, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
    sleep(2);   /* both VMs are up and have written their markers by now */

    /* Controls: each shows the matching refusal below is not vacuous. */
    result("control-own-marker-visible", access(mine, F_OK) == 0);
    result("control-own-process-visible", process_named(ME) == 1);
    result("control-host-vsock-reachable", vsock_connects(VMADDR_CID_HOST, 5000));

    result("peer-marker-absent", access(theirs, F_OK) != 0);
    result("peer-process-absent", process_named(other) == 0);
    result("rootfs-not-writable", open("/shared-probe", O_WRONLY | O_CREAT, 0644) < 0);
    /* Every VM has guest CID 3, so a route to "CID 3" or a neighbouring CID would be a peer. */
    result("vsock-cid-3-refused", !vsock_connects(3, 5000));
    result("vsock-cid-4-refused", !vsock_connects(4, 5000));
    result("vsock-cid-1-refused", !vsock_connects(1, 5000));

    snprintf(line, sizeof line, "DONE %s", ME); report(line);
    return 0;
#endif
}
