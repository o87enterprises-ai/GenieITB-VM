#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KVER="6.1.167"
KDIR="$ROOT/kernel/linux-${KVER}"
CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
BACKUP="$ROOT/kernel/vmlinux-4.14-quickstart.bin.bak"

say() { printf '\n==> %s\n' "$*"; }

# --- 1. Build dependencies -------------------------------------------------
if ! command -v pahole >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
  say "Installing kernel build dependencies"
  sudo apt-get update
  sudo apt-get install -y \
    dwarves libncurses-dev cpio rsync kmod \
    flex bison bc libelf-dev libssl-dev
fi

# --- 2. Fetch kernel source ------------------------------------------------
if [ ! -d "$KDIR" ]; then
  say "Downloading Linux ${KVER}"
  mkdir -p "$ROOT/kernel"
  TMP="$(mktemp -d)"
  curl -fsSL -o "$TMP/linux.tar.xz" \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KVER}.tar.xz"
  tar -xf "$TMP/linux.tar.xz" -C "$ROOT/kernel"
  rm -rf "$TMP"
fi

cd "$KDIR"

# --- 3. Start from Firecracker's 6.1 guest config --------------------------
say "Fetching Firecracker 6.1 guest config"
curl -fsSL -o .config "$CONFIG_URL"

# --- 4. Enable required options --------------------------------------------
# The critical fix vs the first build:
#   CONFIG_PCI=y
#     Firecracker issue #4881: the vanilla 6.1 kernel panics with
#     "VFS: Cannot open root device vda" unless PCI is compiled in, because
#     the 6.1 guest config enables ACPI and ACPI init aborts without PCI.
#     The 4.14 quickstart kernel worked because it was built from Amazon Linux,
#     which carries patches that allow ACPI without PCI. Vanilla 6.1 does not.
#   CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
#     Required on x86_64 so the kernel parses virtio_mmio.device=4K@... from
#     the command line and registers /dev/vda. Without it the rootfs device
#     is never discovered.
say "Enabling required options"
scripts/config --file .config \
  --enable  CONFIG_PCI \
  --enable  CONFIG_VIRTIO_MMIO \
  --enable  CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES \
  --enable  CONFIG_VIRTIO_BLK \
  --enable  CONFIG_VSOCKETS \
  --enable  CONFIG_VIRTIO_VSOCKETS \
  --enable  CONFIG_VIRTIO_VSOCKETS_COMMON \
  --enable  CONFIG_SECCOMP \
  --enable  CONFIG_SECCOMP_FILTER \
  --enable  CONFIG_SECURITY \
  --enable  CONFIG_SECURITY_LANDLOCK \
  --set-str CONFIG_LSM "landlock,lockdown,yama,integrity,apparmor" \
  --disable CONFIG_DEBUG_INFO \
  --disable CONFIG_DEBUG_INFO_BTF \
  --disable CONFIG_KASAN \
  --disable CONFIG_KCSAN \
  --disable CONFIG_UBSAN

# --- 5. Reconcile with this source tree ------------------------------------
say "Running olddefconfig"
make olddefconfig

# --- 6. Verify the options survived ----------------------------------------
say "Verifying required symbols"
for sym in \
  CONFIG_PCI \
  CONFIG_VIRTIO_MMIO \
  CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES \
  CONFIG_VIRTIO_BLK \
  CONFIG_VSOCKETS \
  CONFIG_VIRTIO_VSOCKETS \
  CONFIG_SECCOMP \
  CONFIG_SECCOMP_FILTER \
  CONFIG_SECURITY \
  CONFIG_SECURITY_LANDLOCK
do
  if ! grep -q "^${sym}=y" .config; then
    echo "ERROR: ${sym} is not enabled in .config"
    exit 1
  fi
done

if ! grep '^CONFIG_LSM=' .config | grep -q landlock; then
  echo "ERROR: landlock is not present in CONFIG_LSM"
  grep '^CONFIG_LSM=' .config || true
  exit 1
fi
echo "All required symbols are enabled."

# --- 7. Build the uncompressed vmlinux -------------------------------------
say "Building vmlinux (this takes 10-20 minutes on a cold tree)"
make vmlinux -j"$(nproc)"

# --- 8. Verify the binary contains the symbols we need ---------------------
# grep -a on the binary rather than `strings | grep -q`: under set -o pipefail
# the latter returns 141 when grep closes the pipe early, which `!` inverts
# into a false negative.
say "Verifying built kernel contains virtio_blk, virtio_mmio and vsock"
for pat in virtio_blk virtio_mmio vsock; do
  if ! grep -qa "$pat" vmlinux; then
    echo "ERROR: built vmlinux has no '$pat' symbols"
    exit 1
  fi
  echo "OK: '$pat' present in vmlinux"
done

# --- 9. Install the new kernel ---------------------------------------------
say "Installing new kernel"
[ -f "$ROOT/kernel/vmlinux.bin" ] && [ ! -f "$BACKUP" ] && cp "$ROOT/kernel/vmlinux.bin" "$BACKUP"
cp vmlinux "$ROOT/kernel/vmlinux.bin"

ls -lh "$ROOT/kernel/vmlinux.bin"
say "Kernel replaced with 6.1 + PCI + virtio-mmio + vsock + Landlock."
say "Backup: $BACKUP"
say "Next:   ./03-setup.sh && ./03-boot-vsock.sh"
