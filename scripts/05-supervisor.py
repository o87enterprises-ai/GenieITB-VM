#!/usr/bin/env python3
"""Phase 5 SS1 supervisor: boots the microVM with /init -> /05-supervisor,
which mounts proc/sys/tmpfs, then forks doc_agent + shell_agent.

Wire protocol (handoff §7): the guest opens a fresh AF_VSOCK connection
per line; the host commits the line to the hash chain, then sends `ack\\n`.
The guest refuses to proceed without an ack (receipt not committed).

Guest powers itself off after DONE supervisor (default run) or after
TRIPWIRE (kill run). We just wait for Firecracker to exit.
"""
import argparse, http.client, importlib.util, json, os, socket, subprocess, sys, tempfile, threading, time

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "receipt5", os.path.join(_HERE, "05-receipt.py"))
receipt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(receipt)

def wait_for_socket(path, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            time.sleep(0.05); return
        time.sleep(0.02)
    raise RuntimeError(f"API socket {path} did not appear within {timeout}s")

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout=5.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout); s.connect(self.socket_path); self.sock = s

def api_put(sock_path, path, body):
    conn = UnixHTTPConnection(sock_path)
    try:
        payload = json.dumps(body).encode()
        conn.request("PUT", path, body=payload, headers={"Content-Type": "application/json"})
        resp = conn.getresponse(); data = resp.read()
        if resp.status >= 300:
            raise RuntimeError(f"PUT {path} -> {resp.status}: {data!r}")
        return data
    finally:
        conn.close()

def run_vsock_listener(listen_path, events_path, receipt_db, ready_event, stop_event):
    try: os.unlink(listen_path)
    except FileNotFoundError: pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(listen_path); sock.listen(8); sock.settimeout(1.0)
    ready_event.set()
    try:
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5.0)
                buf = b""
                truncated = False
                try:
                    while b"\n" not in buf:
                        if len(buf) >= 16384:
                            truncated = True
                            break
                        chunk = conn.recv(4096)
                        if not chunk: break
                        buf += chunk
                except socket.timeout:
                    pass
                if not buf:
                    continue
                if truncated and b"\n" not in buf:
                    # F3: a line exceeding the cap with no newline must NOT be
                    # committed as if it were a whole line — that records a lie.
                    # Record the truncation as its own event and refuse to ack;
                    # the guest's send_and_ack fails closed on a missing ack.
                    marker = f"TRUNCATION vsock line exceeded 16384 bytes dropped={len(buf)}"
                    with open(events_path, "ab") as f:
                        f.write(marker.encode() + b"\n")
                    try:
                        receipt.append_run_event(receipt_db, "vsock", marker)
                    except Exception as e:
                        print(f"supervisor: RECEIPT WRITE FAILED on truncation: {e}",
                              file=sys.stderr)
                    continue  # no ack
                line = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
                with open(events_path, "ab") as f:
                    f.write(line.encode() + b"\n")
                try:
                    receipt.append_run_event(receipt_db, "vsock", line)
                except Exception as e:
                    print(f"supervisor: RECEIPT WRITE FAILED, refusing to ack: {e}",
                          file=sys.stderr)
                    continue
                try: conn.sendall(b"ack\n")
                except OSError: pass
                if line == "HALT supervisor":
                    stop_event.set()
                    break
    finally:
        sock.close()
        try: os.unlink(listen_path)
        except FileNotFoundError: pass

def dump_serial_tail(serial_path, n=40):
    try:
        data = open(serial_path, "rb").read()
        print("--- serial log tail ---", file=sys.stderr)
        for line in data.split(b"\n")[-n:]:
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
    ap.add_argument("--receipt-db", required=True)
    ap.add_argument("--init-target", default="/init", choices=["/init", "/init-trip"])
    ap.add_argument("--run-timeout", type=float, default=60.0)
    args = ap.parse_args()

    boot_args = ("console=ttyS0 reboot=k panic=1 pci=off "
                 "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd "
                 f"init={args.init_target}")
    open(args.events_log, "wb").close()

    with tempfile.TemporaryDirectory(prefix="fc-supervisor-05-") as tmp:
        api_sock = os.path.join(tmp, "fc.sock")
        uds_prefix = os.path.join(tmp, "fc-vsock.sock")
        uds_listen = uds_prefix + "_5000"
        ready_event = threading.Event(); stop_event = threading.Event()
        listener_thread = threading.Thread(target=run_vsock_listener,
            args=(uds_listen, args.events_log, args.receipt_db, ready_event, stop_event),
            daemon=True)
        listener_thread.start()
        if not ready_event.wait(timeout=2.0):
            print("supervisor: vsock listener did not become ready", file=sys.stderr)
            return 1

        serial_f = open(args.serial_log, "wb")
        proc = None; rc = None
        try:
            proc = subprocess.Popen([args.firecracker, "--api-sock", api_sock],
                stdin=subprocess.DEVNULL,
                stdout=serial_f, stderr=subprocess.STDOUT)
            wait_for_socket(api_sock)
            api_put(api_sock, "/boot-source", {
                "kernel_image_path": args.kernel, "boot_args": boot_args})
            api_put(api_sock, "/drives/rootfs", {
                "drive_id": "rootfs", "path_on_host": args.rootfs,
                "is_root_device": True, "is_read_only": True})
            api_put(api_sock, "/machine-config", {
                "vcpu_count": 1, "mem_size_mib": 256, "smt": False})
            api_put(api_sock, "/vsock", {"guest_cid": 3, "uds_path": uds_prefix})
            api_put(api_sock, "/actions", {"action_type": "InstanceStart"})
            try:
                rc = proc.wait(timeout=args.run_timeout)
            except subprocess.TimeoutExpired:
                print(f"supervisor: Firecracker did not exit within {args.run_timeout}s",
                      file=sys.stderr)
                dump_serial_tail(args.serial_log)
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                rc = 124
        finally:
            serial_f.close()
            if proc is not None and proc.poll() is None:
                proc.kill(); proc.wait()
        time.sleep(0.3); stop_event.set(); listener_thread.join(timeout=2.0)
        print(f"supervisor: Firecracker exit code {rc}", file=sys.stderr)
        try:
            ok, msg = receipt.verify(args.receipt_db)
            print(f"supervisor: receipt {msg} ({'OK' if ok else 'BROKEN'})", file=sys.stderr)
        except Exception as e:
            print(f"supervisor: receipt check failed: {e}", file=sys.stderr)
        return 0

if __name__ == "__main__":
    sys.exit(main())
