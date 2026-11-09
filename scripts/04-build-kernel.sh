#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KVER="6.1.167"
KDIR="$ROOT/kernel/linux-${KVER}"
CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
VENDORED_CONFIG="$ROOT/config/guest-kernel-6.1.config"
# EXT-07: never overwrite the known-good kernel; write alongside and promote after SS1 passes.
KERNEL_OUT="${KERNEL_OUT:-$ROOT/kernel/vmlinux-hardened.bin}"
JOBS="${JOBS:-$(nproc)}"

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
  "$ROOT/scripts/verify-inputs.sh" "linux-${KVER}.tar.xz" "$TMP/linux.tar.xz"
  tar -xf "$TMP/linux.tar.xz" -C "$ROOT/kernel"
  rm -rf "$TMP"
fi

cd "$KDIR"

# --- 3. Start from Firecracker's 6.1 guest config --------------------------
if [ -f "$VENDORED_CONFIG" ]; then
  say "Using vendored guest config $VENDORED_CONFIG"
  "$ROOT/scripts/verify-inputs.sh" config/guest-kernel-6.1.config "$VENDORED_CONFIG"
  cp "$VENDORED_CONFIG" .config
else
  say "WARNING: no vendored config; fetching from a moving branch (EXT-05). Vendor the result."
  curl -fsSL -o .config "$CONFIG_URL"
fi

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
  --set-str CONFIG_LSM "landlock,lockdown,yama" \
  --enable  CONFIG_SECURITY_LOCKDOWN_LSM \
  --enable  CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY \
  --enable  CONFIG_SECURITY_YAMA \
  --enable  CONFIG_SECURITY_DMESG_RESTRICT \
  --enable  CONFIG_INIT_ON_ALLOC_DEFAULT_ON \
  --enable  CONFIG_EXPERT \
  --disable CONFIG_IO_URING --disable CONFIG_USER_NS --disable CONFIG_BPF_SYSCALL \
  --disable CONFIG_USERFAULTFD --disable CONFIG_CHECKPOINT_RESTORE \
  --disable CONFIG_DEBUG_FS --disable CONFIG_MAGIC_SYSRQ --disable CONFIG_KEXEC_FILE \
  --disable CONFIG_UEVENT_HELPER --disable CONFIG_IA32_EMULATION \
  --disable CONFIG_NETFILTER --disable CONFIG_PACKET --disable CONFIG_VIRTIO_NET \
  --disable CONFIG_INET \
  --disable CONFIG_PROC_KCORE --disable CONFIG_X86_MSR --disable CONFIG_X86_CPUID \
  --disable CONFIG_LEGACY_VSYSCALL_XONLY --disable CONFIG_LEGACY_VSYSCALL_EMULATE \
  --enable  CONFIG_LEGACY_VSYSCALL_NONE \
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
"$ROOT/scripts/audit-kernel-config.sh" .config

# --- 7. Build the uncompressed vmlinux -------------------------------------
say "Building vmlinux (this takes 10-20 minutes on a cold tree)"
make vmlinux -j"$JOBS"

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

# --- 9. Install alongside, never over the working kernel ------------------
say "Writing $KERNEL_OUT"
cp vmlinux "$KERNEL_OUT"
# Only seed the vendored config once; afterwards it is pinned in inputs.lock.
[ -f "$VENDORED_CONFIG" ] || { mkdir -p "$ROOT/config"; cp .config "$VENDORED_CONFIG"; }
sha256sum "$KERNEL_OUT"
ls -lh "$KERNEL_OUT"
say "Test:    KERNEL=$KERNEL_OUT ./scripts/05-boot-attack.sh default && ... kill"
say "Promote: cp $KERNEL_OUT kernel/vmlinux.bin   (only after both SS1 modes pass)"
