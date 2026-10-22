#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

/* musl does not ship <linux/vm_sockets.h>. Define what we need locally.
 * These values are stable Linux UAPI ABI (since 4.8). */
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST 2
#endif

struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int   svm_port;
    unsigned int   svm_cid;
    unsigned char  svm_zero[sizeof(struct sockaddr) -
                            sizeof(unsigned short) -
                            sizeof(unsigned short) -
                            sizeof(unsigned int) -
                            sizeof(unsigned int)];
};

int main(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { perror("agent: socket"); return 1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid    = VMADDR_CID_HOST;
    addr.svm_port   = 5000;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("agent: connect");
        return 2;
    }

    const char *hello = "hello from guest\n";
    if (write(fd, hello, strlen(hello)) < 0) {
        perror("agent: write");
        return 3;
    }

    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) { perror("agent: read"); return 4; }
    printf("agent: ack: %s", buf);
    fflush(stdout);
    close(fd);
    return 0;
}
