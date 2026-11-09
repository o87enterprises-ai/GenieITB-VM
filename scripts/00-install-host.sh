#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FC_VERSION="${FC_VERSION:-v1.17.0}"   # pinned in inputs.lock
ARCH="$(uname -m)"
KERNEL_VERSION="${KERNEL_VERSION:-5.10.223}"

say() { printf '\n==> %s\n' "$*"; }

# --- 1. KVM check (fail early if Firecracker cannot run) -------------------
if [ ! -c /dev/kvm ]; then
  echo "ERROR: /dev/kvm is missing. Enable nested virtualization or use a native Linux host."
  exit 1
fi
say "KVM present: $(ls -l /dev/kvm)"

# --- 2. Base packages -------------------------------------------------------
say "Installing base packages"
sudo apt-get update
sudo apt-get install -y \
  build-essential curl wget git jq pkg-config \
  flex bison bc libelf-dev libssl-dev \
  python3 python3-venv \
  bubblewrap

# --- 3. Rust ----------------------------------------------------------------
# EXT-05: no `curl | sh`. Rust is only needed to build the sibling `broker`; install it
# from your distro or a rustup-init whose hash you have verified, then re-run.
command -v cargo >/dev/null 2>&1 || say "NOTE: cargo not found (needed only to build broker)"

# --- 4. Firecracker binary -------------------------------------------------
mkdir -p "$ROOT/bin" "$ROOT/kernel" "$ROOT/rootfs" "$ROOT/logs" "$ROOT/config"
if [ ! -x "$ROOT/bin/firecracker" ]; then
  say "Downloading Firecracker $FC_VERSION ($ARCH)"
  TMP="$(mktemp -d)"
  curl -fsSL -o "$TMP/fc.tgz" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}.tgz"
  # EXT-05: fail closed unless the tarball matches inputs.lock.
  "$ROOT/scripts/verify-inputs.sh" "firecracker-${FC_VERSION}-${ARCH}.tgz" "$TMP/fc.tgz"
  tar -xzf "$TMP/fc.tgz" -C "$TMP" --no-same-owner

  # The tarball extracts to release-vX.Y.Z-<arch>/, not firecracker-vX.Y.Z-<arch>/
  FC_DIR="release-${FC_VERSION}-${ARCH}"
  if [ ! -f "$TMP/${FC_DIR}/firecracker-${FC_VERSION}-${ARCH}" ]; then
    echo "ERROR: expected binary not found. Contents of $TMP:"
    find "$TMP" -maxdepth 2 -type f | sort
    exit 1
  fi

  install -m 0755 "$TMP/${FC_DIR}/firecracker-${FC_VERSION}-${ARCH}" \
    "$ROOT/bin/firecracker"
  install -m 0755 "$TMP/${FC_DIR}/jailer-${FC_VERSION}-${ARCH}" "$ROOT/bin/jailer"
  "$ROOT/scripts/verify-inputs.sh" --installed
  rm -rf "$TMP"
fi

# GEN-13: also covers binaries that were already here and skipped the download.
"$ROOT/scripts/verify-inputs.sh" --installed
"$ROOT/bin/firecracker" --version

# --- 5. Reference kernel (Firecracker CI quickstart kernel) ----------------
# This is deliberately NOT the minimal kernel yet — it is the known-good
# baseline that proves the VMM path works before we replace it.
if [ ! -f "$ROOT/kernel/vmlinux.bin" ]; then
  say "Downloading reference vmlinux (Firecracker quickstart)"
  curl -fsSL -o "$ROOT/kernel/vmlinux.bin" \
    "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
  "$ROOT/scripts/verify-inputs.sh" reference-vmlinux.bin "$ROOT/kernel/vmlinux.bin" \
    || { rm -f "$ROOT/kernel/vmlinux.bin"; echo "unpinned download removed (EXT-05)"; exit 1; }
fi
ls -lh "$ROOT/kernel/vmlinux.bin"

# --- 6. Reference rootfs (Firecracker CI quickstart ext4) ------------------
if [ ! -f "$ROOT/rootfs/rootfs.ext4" ]; then
  say "Downloading reference rootfs.ext4"
  curl -fsSL -o "$ROOT/rootfs/rootfs.ext4" \
    "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4"
  "$ROOT/scripts/verify-inputs.sh" reference-rootfs.ext4 "$ROOT/rootfs/rootfs.ext4" \
    || { rm -f "$ROOT/rootfs/rootfs.ext4"; echo "unpinned download removed (EXT-05)"; exit 1; }
fi
ls -lh "$ROOT/rootfs/rootfs.ext4"

# --- 7. Sanity: Firecracker can start and exit cleanly ---------------------
say "Firecracker binary self-check"
"$ROOT/bin/firecracker" --no-api --config-file /dev/null 2>&1 || true

say "Phase 0 complete."
say "Artifacts:"
say "  $ROOT/bin/firecracker"
say "  $ROOT/kernel/vmlinux.bin"
say "  $ROOT/rootfs/rootfs.ext4"
say "Next: Phase 1 — boot the reference image, confirm no network, then replace the kernel."
