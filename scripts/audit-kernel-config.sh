#!/usr/bin/env bash
# EXT-07: fail if the guest kernel .config enables anything on the deny list or lacks
# anything on the require list. Run after `make olddefconfig` (dependencies can silently
# re-enable options) and again in CI.
#   usage: audit-kernel-config.sh <path/to/.config>
set -euo pipefail
CFG="${1:?usage: $0 <.config>}"
fail=0

# Needed by this workload (supervisor uses socketpair(AF_UNIX); agents use vsock).
REQUIRE=(
  SECCOMP SECCOMP_FILTER SECURITY SECURITY_LANDLOCK VSOCKETS VIRTIO_VSOCKETS
  VIRTIO_BLK VIRTIO_MMIO UNIX
  SECURITY_LOCKDOWN_LSM SECURITY_YAMA SECURITY_DMESG_RESTRICT
  INIT_ON_ALLOC_DEFAULT_ON STRICT_KERNEL_RWX RANDOMIZE_BASE HARDENED_USERCOPY
  SLAB_FREELIST_HARDENED VMAP_STACK STACKPROTECTOR_STRONG FORTIFY_SOURCE RANDOMIZE_MEMORY
)
# Not needed by this workload; each is attack surface (see SECURITY_REVIEW.md EXT-07).
DENY=(
  IO_URING USER_NS BPF_SYSCALL USERFAULTFD CHECKPOINT_RESTORE DEBUG_FS MAGIC_SYSRQ
  KEXEC KEXEC_FILE UEVENT_HELPER IA32_EMULATION X86_X32_ABI MODULES DEVMEM
  NETFILTER PACKET VIRTIO_NET INET
  PROC_KCORE X86_MSR X86_CPUID KPROBES FTRACE LEGACY_VSYSCALL_XONLY LEGACY_VSYSCALL_EMULATE
)

for s in "${REQUIRE[@]}"; do
  grep -q "^CONFIG_${s}=y" "$CFG" || { echo "MISSING required CONFIG_${s}"; fail=1; }
done
for s in "${DENY[@]}"; do
  if grep -qE "^CONFIG_${s}=[ym]" "$CFG"; then echo "ENABLED denied CONFIG_${s}"; fail=1; fi
done

# CONFIG_LSM must only name modules that are actually built in (a name that is
# compiled out suggests protection that is not there).
lsm="$(sed -n 's/^CONFIG_LSM="\(.*\)"/\1/p' "$CFG")"
for m in ${lsm//,/ }; do
  case "$m" in
    landlock)  sym=SECURITY_LANDLOCK ;;
    lockdown)  sym=SECURITY_LOCKDOWN_LSM ;;
    yama)      sym=SECURITY_YAMA ;;
    integrity) sym=INTEGRITY ;;
    apparmor)  sym=SECURITY_APPARMOR ;;
    *)         sym="" ;;
  esac
  [[ -z "$sym" ]] || grep -q "^CONFIG_${sym}=y" "$CFG" || { echo "CONFIG_LSM lists '$m' but CONFIG_${sym} is not built in"; fail=1; }
done

[[ $fail -eq 0 ]] && echo "kernel config audit: PASS" || { echo "kernel config audit: FAIL"; exit 1; }
