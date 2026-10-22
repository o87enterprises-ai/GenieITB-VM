#!/usr/bin/env python3
"""
Phase 2 supervisor: boot Firecracker through its API socket.

Why this replaces --no-api:
  --no-api cannot be controlled at runtime. The only ways to stop it are
  SIGTERM or `timeout`, and nothing can be reconfigured after boot. Later
  phases (vsock in Phase 3, log in Phase 4, tripwire in Phase 5) all need
  runtime control, so this phase establishes it.

This script does NOT yet add vsock, the log, or the tripwire. It proves
the control plane works and preserves the Phase 1 assertions unchanged.
"""

import argparse
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time


def wait_for_socket(path, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            time.sleep(0.05)  # let the listener bind
            return
        time.sleep(0.02)
    raise RuntimeError(f"API socket {path} did not appear within {timeout}s")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout=5.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.socket_path)
        self.sock = s


def api_put(sock_path, path, body):
    conn = UnixHTTPConnection(sock_path)
    try:
        payload = json.dumps(body).encode()
        conn.request("PUT", path, body=payload,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        if resp.status >= 300:
            raise RuntimeError(f"PUT {path} -> {resp.status}: {data!r}")
        return data
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firecracker", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--run-timeout", type=float, default=15.0)
    args = ap.parse_args()

    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/bin/sh"
    )

    # The shell commands are identical to Phase 1 so the assertions still work.
    shell_script = (
        "export PATH=/sbin:/usr/sbin:/bin:/usr/bin\n"
        "mount -t proc proc /proc 2>/dev/null || true\n"
        "mount -t sysfs sysfs /sys 2>/dev/null || true\n"
        "echo ===IP_LINK===\n"
        "ip -o link show\n"
        "echo ===TCP===\n"
        "cat /proc/net/tcp 2>/dev/null || true\n"
        "echo ===TCP6===\n"
        "cat /proc/net/tcp6 2>/dev/null || true\n"
        "echo ===END===\n"
        "poweroff -f\n"
    )

    with tempfile.TemporaryDirectory(prefix="fc-supervisor-") as tmp:
        api_sock = os.path.join(tmp, "fc.sock")
        log_f = open(args.log, "wb")
        try:
            proc = subprocess.Popen(
                [args.firecracker, "--api-sock", api_sock],
                stdin=subprocess.PIPE,
                stdout=log_f,
                stderr=subprocess.STDOUT,
            )
            try:
                wait_for_socket(api_sock)

                api_put(api_sock, "/boot-source", {
                    "kernel_image_path": args.kernel,
                    "boot_args": boot_args,
                })
                api_put(api_sock, "/drives/rootfs", {
                    "drive_id": "rootfs",
                    "path_on_host": args.rootfs,
                    "is_root_device": True,
                    "is_read_only": True,
                })
                api_put(api_sock, "/machine-config", {
                    "vcpu_count": 1,
                    "mem_size_mib": 256,
                    "smt": False,
                })
                api_put(api_sock, "/actions", {"action_type": "InstanceStart"})

                # Give init=/bin/sh time to start before feeding commands.
                time.sleep(3)
                proc.stdin.write(shell_script.encode())
                proc.stdin.flush()
                proc.stdin.close()

                # Firecracker exits non-zero when the guest halts first; that
                # is expected. Treat 124 as "we killed it after the timeout".
                try:
                    rc = proc.wait(timeout=args.run_timeout)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    rc = 124
            finally:
                log_f.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

            print(f"supervisor: Firecracker exit code {rc}", file=sys.stderr)
            return 0
        finally:
            if not log_f.closed:
                log_f.close()


if __name__ == "__main__":
    sys.exit(main())
