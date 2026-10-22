#!/usr/bin/env python3
"""
Phase 3 supervisor: boot Firecracker with a virtio-vsock device.

Adds (vs Phase 2):
  - PUT /vsock with guest_cid=3, uds_path=<tmpdir>/fc-vsock.sock
  - A UDS listener on <uds_path>_5000 so the guest can reach the host
    at CID 2 : port 5000
  - Every byte received over vsock is written to the events log on the
    host. This is the seed of the incident receipt.
  - On Firecracker early exit, dump the serial tail to stderr so the
    caller sees why instead of a BrokenPipeError traceback.
"""

import argparse
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time


def wait_for_socket(path, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            time.sleep(0.05)
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


def run_vsock_listener(listen_path, events_path, ready_event, stop_event):
    try:
        os.unlink(listen_path)
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(listen_path)
    sock.listen(4)
    sock.settimeout(1.0)
    ready_event.set()
    try:
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5.0)
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    data = b""
                if data:
                    with open(events_path, "ab") as f:
                        f.write(data)
                    try:
                        conn.sendall(b"ack\n")
                    except OSError:
                        pass
    finally:
        sock.close()
        try:
            os.unlink(listen_path)
        except FileNotFoundError:
            pass


def dump_serial_tail(serial_path, n=40):
    try:
        with open(serial_path, "rb") as f:
            data = f.read()
        lines = data.split(b"\n")[-n:]
        print("--- serial log tail ---", file=sys.stderr)
        for line in lines:
            print(line.decode("utf-8", "replace").rstrip("\r"), file=sys.stderr)
        print("--- end serial log tail ---", file=sys.stderr)
    except Exception as e:
        print(f"(failed to read serial log: {e})", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firecracker", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--serial-log", required=True)
    ap.add_argument("--events-log", required=True)
    ap.add_argument("--run-timeout", type=float, default=15.0)
    args = ap.parse_args()

    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/bin/sh"
    )

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
        "echo ===VSOCK===\n"
        "/agent || echo 'agent failed'\n"
        "echo ===VSOCK_DONE===\n"
        "echo ===END===\n"
        "poweroff -f\n"
    )

    open(args.events_log, "wb").close()

    with tempfile.TemporaryDirectory(prefix="fc-supervisor-") as tmp:
        api_sock = os.path.join(tmp, "fc.sock")
        uds_prefix = os.path.join(tmp, "fc-vsock.sock")
        uds_listen = uds_prefix + "_5000"

        ready_event = threading.Event()
        stop_event = threading.Event()
        listener_thread = threading.Thread(
            target=run_vsock_listener,
            args=(uds_listen, args.events_log, ready_event, stop_event),
            daemon=True,
        )
        listener_thread.start()
        if not ready_event.wait(timeout=2.0):
            print("supervisor: vsock listener did not become ready",
                  file=sys.stderr)
            return 1

        serial_f = open(args.serial_log, "wb")
        proc = None
        rc = None
        try:
            proc = subprocess.Popen(
                [args.firecracker, "--api-sock", api_sock],
                stdin=subprocess.PIPE,
                stdout=serial_f,
                stderr=subprocess.STDOUT,
            )
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
            api_put(api_sock, "/vsock", {
                "guest_cid": 3,
                "uds_path": uds_prefix,
            })
            api_put(api_sock, "/actions", {"action_type": "InstanceStart"})

            # Brief pause: if the kernel doesn't boot, Firecracker exits
            # quickly and we want to know that before writing to stdin.
            time.sleep(3.0)
            if proc.poll() is not None:
                print(f"supervisor: Firecracker exited during boot "
                      f"(code {proc.returncode}) before shell input",
                      file=sys.stderr)
                dump_serial_tail(args.serial_log)
                rc = proc.returncode
            else:
                try:
                    proc.stdin.write(shell_script.encode())
                    proc.stdin.flush()
                    proc.stdin.close()
                except (BrokenPipeError, OSError) as e:
                    print(f"supervisor: could not write to Firecracker stdin: {e}",
                          file=sys.stderr)
                    dump_serial_tail(args.serial_log)

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
            serial_f.close()
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()

        time.sleep(0.3)
        stop_event.set()
        listener_thread.join(timeout=2.0)

        print(f"supervisor: Firecracker exit code {rc}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
