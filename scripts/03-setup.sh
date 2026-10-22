#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$ROOT/guest-agent"
ROOTFS_SRC="$ROOT/rootfs/rootfs.ext4"
ROOTFS_DST="$ROOT/rootfs/rootfs-vsock.ext4"

say() { printf '\n==> %s\n' "$*"; }

# --- 1. musl ---------------------------------------------------------------
if ! command -v musl-gcc >/dev/null 2>&1; then
  say "Installing musl-tools"
  sudo apt-get update
  sudo apt-get install -y musl-tools
fi

# --- 2. Agent --------------------------------------------------------------
say "Writing and compiling guest agent"
mkdir -p "$AGENT_DIR"
cat > "$AGENT_DIR/agent.c" <<'CEOF'
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
CEOF

musl-gcc -static -O2 -o "$AGENT_DIR/agent" "$AGENT_DIR/agent.c"
ls -lh "$AGENT_DIR/agent"

# --- 3. Kernel vsock check (robust; no pipefail/SIGPIPE trap) --------------
# We grep -a directly on the binary. This searches the same byte stream that
# `strings` extracts, but avoids the pipeline: with `set -o pipefail`, a
# `strings hugefile | grep -q pattern` pipeline returns 141 when grep closes
# the pipe early after finding a match, which `!` inverts into a false
# "symbol not found". grep -a on the file has no such interaction.
say "Checking kernel for vsock support"
if ! grep -qaE 'virtio_vsock_init|virtio_transport_common|vsock_stream|the_virtio_vsock' \
     "$ROOT/kernel/vmlinux.bin"; then
  echo "ERROR: kernel has no vsock symbols."
  echo "       Checked: $ROOT/kernel/vmlinux.bin"
  echo "       Expected one of: virtio_vsock_init, virtio_transport_common,"
  echo "                        vsock_stream, the_virtio_vsock"
  echo ""
  echo "       To proceed anyway, re-run with ALLOW_NO_VSOCK=1"
  if [ "${ALLOW_NO_VSOCK:-0}" != "1" ]; then
    exit 1
  fi
fi
echo "OK: kernel contains vsock symbols"

# --- 4. Rootfs copy + inject ----------------------------------------------
if [ ! -f "$ROOTFS_SRC" ]; then
  echo "ERROR: $ROOTFS_SRC missing — run 00-install-host.sh first"
  exit 1
fi

say "Copying reference rootfs to $ROOTFS_DST"
cp -f "$ROOTFS_SRC" "$ROOTFS_DST"

say "Injecting /agent into the copy"
MNT="$(mktemp -d)"
sudo mount -o loop "$ROOTFS_DST" "$MNT"
sudo cp "$AGENT_DIR/agent" "$MNT/agent"
sudo chmod 0755 "$MNT/agent"
sudo umount "$MNT"

say "Verifying injection"
sudo mount -o loop,ro "$ROOTFS_DST" "$MNT"
ls -l "$MNT/agent"
sudo umount "$MNT"
rmdir "$MNT"

say "Phase 3 setup complete."
say "Agent:   $AGENT_DIR/agent"
say "Rootfs:  $ROOTFS_DST"
say "Next:    ./03-boot-vsock.sh"
