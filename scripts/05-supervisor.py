#!/usr/bin/env python3
"""Phase 5 SS1 supervisor: boots the microVM with /init -> /05-supervisor,
which mounts proc/sys/tmpfs, then forks doc_agent + shell_agent.

Wire protocol (handoff §7): the guest opens a fresh AF_VSOCK connection
per line; the host commits the line to the hash chain, then sends `ack\\n`.
The guest refuses to proceed without an ack (receipt not committed).

Guest powers itself off after DONE supervisor (default run) or after
TRIPWIRE (kill run). We just wait for Firecracker to exit.
"""
import argparse, http.client, importlib.util, json, os, shutil, signal, socket, stat, subprocess, sys, tempfile, threading, time

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

def api_get(sock_path, path):
    conn = UnixHTTPConnection(sock_path)
    try:
        conn.request("GET", path)
        resp = conn.getresponse(); data = resp.read()
        if resp.status >= 300:
            raise RuntimeError(f"GET {path} -> {resp.status}: {data!r}")
        return json.loads(data)
    finally:
        conn.close()

def assert_no_network(sock_path):
    """EXT-01: the no-NIC property must be enforced, not assumed. Abort before
    InstanceStart if the VM config carries any network interface or MMDS."""
    cfg = api_get(sock_path, "/vm/config")
    nics = cfg.get("network-interfaces") or []
    if nics:
        raise RuntimeError(f"REFUSING TO START: {len(nics)} network interface(s) configured "
                           "and no ingress/egress policy exists (see HANDOFF_PERIMETER.md)")
    if cfg.get("mmds-config"):
        raise RuntimeError("REFUSING TO START: MMDS configured")

def bind_listener(listen_path, owner=None):
    try: os.unlink(listen_path)
    except FileNotFoundError: pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(listen_path)
    if owner is not None:
        os.chown(listen_path, owner[0], owner[1])
        os.chmod(listen_path, 0o600)
    sock.listen(8); sock.settimeout(1.0)
    return sock

def run_vsock_listener(sock, listen_path, events_path, receipt_db, ready_event, stop_event):
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
        except OSError: pass   # in jail mode the jail teardown removes it

def dump_serial_tail(serial_path, n=40):
    try:
        data = open(serial_path, "rb").read()
        print("--- serial log tail ---", file=sys.stderr)
        for line in data.split(b"\n")[-n:]:
            print(line.decode("utf-8", "replace").rstrip("\r"), file=sys.stderr)
        print("--- end serial log tail ---", file=sys.stderr)
    except Exception as e:
        print(f"(failed to read serial log: {e})", file=sys.stderr)

# --- EXT-03: jailed launch --------------------------------------------------
JAIL_MEMORY_MAX = 384 * 1024 * 1024   # 256 MiB guest + VMM overhead
JAIL_API_SOCK, JAIL_UDS = "/api.sock", "/fc-vsock.sock"
EXIT_STOPPED = 3   # the caller asked for the VM to be stopped (tripwire)

def prepare_jail(args, jail_id):
    """Create the chroot and copy boot artifacts in. Runs as root."""
    exec_name = os.path.basename(args.firecracker)
    if "firecracker" not in exec_name:
        raise RuntimeError("jailer requires the exec file name to contain 'firecracker'")
    base = args.chroot_base
    os.makedirs(base, mode=0o755, exist_ok=True)
    st = os.lstat(base)
    # CVE-2026-1386 class: the base must be a real root-owned directory.
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"{base} must be a root-owned directory not writable by others")
    os.makedirs(os.path.join(base, exec_name), mode=0o755, exist_ok=True)
    jail_dir = os.path.join(base, exec_name, jail_id)
    root = os.path.join(jail_dir, "root")
    os.mkdir(jail_dir, 0o755)   # fails if it already exists
    os.mkdir(root, 0o755)
    for src, name in ((args.kernel, "vmlinux.bin"), (args.rootfs, "rootfs.ext4")):
        dst = os.path.join(root, name)
        shutil.copyfile(src, dst)
        os.chown(dst, args.jail_uid, args.jail_gid)
        os.chmod(dst, 0o440)
    os.chown(root, args.jail_uid, args.jail_gid)
    return jail_dir, root

def jailer_argv(args, jail_id):
    return [args.jailer, "--id", jail_id, "--exec-file", os.path.realpath(args.firecracker),
            "--uid", str(args.jail_uid), "--gid", str(args.jail_gid),
            "--chroot-base-dir", args.chroot_base, "--cgroup-version", "2", "--new-pid-ns",
            "--cgroup", f"memory.max={JAIL_MEMORY_MAX}",
            "--cgroup", "cpu.max=100000 100000",
            "--cgroup", "pids.max=64",
            "--", "--api-sock", JAIL_API_SOCK]

def teardown_jail(jail_dir, exec_name, jail_id):
    shutil.rmtree(jail_dir, ignore_errors=True)   # does not follow symlinks
    # A just-killed VMM can keep the cgroup busy briefly.
    for _ in range(30):
        try:
            os.rmdir(f"/sys/fs/cgroup/{exec_name}/{jail_id}")
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.1)
    print(f"supervisor: could not remove cgroup for {jail_id}", file=sys.stderr)

def drop_privileges(uid, gid):
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.geteuid() != uid or os.getegid() != gid:
        raise RuntimeError("failed to drop privileges")

def vm_alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False

def check_confined(pid, jail_uid):
    """EXT-03 acceptance, checked against the live process. Any mismatch fails the run."""
    status = open(f"/proc/{pid}/status").read()
    field = lambda k: next(l.split()[1:] for l in status.splitlines() if l.startswith(k + ":"))
    uid, nspid = field("Uid"), field("NSpid")
    if any(int(u) != jail_uid for u in uid):
        raise RuntimeError(f"VMM uid is {uid}, expected {jail_uid}")
    if len(nspid) < 2:
        raise RuntimeError("VMM is not in its own PID namespace")
    if not os.path.exists(f"/proc/{pid}/root/vmlinux.bin") or os.path.exists(f"/proc/{pid}/root/home"):
        raise RuntimeError("VMM root is not the chroot")
    cg = open(f"/proc/{pid}/cgroup").read().strip().split("::", 1)[1]
    mem = open(f"/sys/fs/cgroup{cg}/memory.max").read().strip()
    if mem != str(JAIL_MEMORY_MAX):
        raise RuntimeError(f"memory.max is {mem}, expected {JAIL_MEMORY_MAX}")
    print(f"supervisor: JAIL CONFIRMED uid={uid[0]} nspid={'/'.join(nspid)} "
          f"cgroup={cg} memory.max={mem}", file=sys.stderr)

def run_vmm(args, boot_args, argv, api_sock, kernel, rootfs, uds_path, pid_file=None,
            stop=None, after_vsock=None):
    """Launch the VMM, configure it, and wait for it. Returns its exit code."""
    serial_f = open(args.serial_log, "wb")
    proc = None; rc = None; vm_pid = None
    stopped = lambda: stop is not None and stop.is_set()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=serial_f, stderr=subprocess.STDOUT)
        wait_for_socket(api_sock)
        api_put(api_sock, "/boot-source", {"kernel_image_path": kernel, "boot_args": boot_args})
        api_put(api_sock, "/drives/rootfs", {
            "drive_id": "rootfs", "path_on_host": rootfs,
            "is_root_device": True, "is_read_only": True})
        api_put(api_sock, "/machine-config", {
            "vcpu_count": 1, "mem_size_mib": 256, "smt": False})
        api_put(api_sock, "/vsock", {"guest_cid": 3, "uds_path": uds_path})
        if after_vsock is not None:
            after_vsock()
        assert_no_network(api_sock)
        api_put(api_sock, "/actions", {"action_type": "InstanceStart"})
        if pid_file is None:
            deadline = time.time() + args.run_timeout
            while proc.poll() is None and time.time() < deadline and not stopped():
                time.sleep(0.02)
            if proc.poll() is not None:
                rc = proc.returncode
            elif stopped():
                proc.kill(); proc.wait()
                rc = EXIT_STOPPED
            else:
                print(f"supervisor: Firecracker did not exit within {args.run_timeout}s",
                      file=sys.stderr)
                dump_serial_tail(args.serial_log)
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                rc = 124
        else:
            # With --new-pid-ns the jailer parent exits and records the VMM's pid.
            parent_rc = proc.wait(timeout=5)
            if parent_rc != 0:
                raise RuntimeError(f"jailer exited {parent_rc}")
            with open(pid_file) as f:
                vm_pid = int(f.read().strip())
            check_confined(vm_pid, args.jail_uid)
            deadline = time.time() + args.run_timeout
            while vm_alive(vm_pid) and time.time() < deadline and not stopped():
                time.sleep(0.02)
            if stopped() and vm_alive(vm_pid):
                rc = EXIT_STOPPED
            elif vm_alive(vm_pid):
                print(f"supervisor: Firecracker did not exit within {args.run_timeout}s",
                      file=sys.stderr)
                dump_serial_tail(args.serial_log)
                rc = 124
            else:
                rc = 0
    finally:
        serial_f.close()
        if proc is not None and proc.poll() is None:
            proc.kill(); proc.wait()
        if vm_pid is not None and vm_alive(vm_pid):
            os.kill(vm_pid, signal.SIGKILL)
    return rc

def finish(args, listener_thread, stop_event, rc):
    time.sleep(0.3); stop_event.set(); listener_thread.join(timeout=2.0)
    print(f"supervisor: Firecracker exit code {rc}", file=sys.stderr)
    try:
        ok, msg = receipt.verify(args.receipt_db)
        print(f"supervisor: receipt {msg} ({'OK' if ok else 'BROKEN'})", file=sys.stderr)
    except Exception as e:
        print(f"supervisor: receipt check failed: {e}", file=sys.stderr)

def start_listener(args, sock, listen_path, stop_event):
    ready_event = threading.Event()
    t = threading.Thread(target=run_vsock_listener,
        args=(sock, listen_path, args.events_log, args.receipt_db, ready_event, stop_event),
        daemon=True)
    t.start()
    if not ready_event.wait(timeout=2.0):
        raise RuntimeError("vsock listener did not become ready")
    return t

def main_jailed(args, boot_args):
    """Root is kept only by the child that launches and tears down the jail. The parent,
    which reads guest-supplied lines and writes receipts, drops to the invoking user."""
    if os.geteuid() != 0 or "SUDO_UID" not in os.environ:
        print("supervisor: jail mode must be started through sudo", file=sys.stderr); return 2
    if not args.jail_uid or not args.jail_gid:
        print("supervisor: --jail-uid/--jail-gid must be non-root", file=sys.stderr); return 2
    owner_uid, owner_gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    exec_name = os.path.basename(args.firecracker)
    jail_id = f"genie-{os.getpid()}"
    jail_dir, root = prepare_jail(args, jail_id)
    listen_path = os.path.join(root, JAIL_UDS.lstrip("/") + "_5000")
    sock = bind_listener(listen_path, owner=(args.jail_uid, args.jail_gid))
    child = os.fork()
    if child == 0:
        rc = 1
        try:
            sock.close()
            rc = run_vmm(args, boot_args, jailer_argv(args, jail_id),
                         os.path.join(root, JAIL_API_SOCK.lstrip("/")),
                         "/vmlinux.bin", "/rootfs.ext4", JAIL_UDS,
                         pid_file=os.path.join(root, f"{exec_name}.pid"))
        except Exception as e:
            print(f"supervisor: jailed launch failed: {e}", file=sys.stderr)
            dump_serial_tail(args.serial_log)
        finally:
            teardown_jail(jail_dir, exec_name, jail_id)
            os._exit(rc)
    drop_privileges(owner_uid, owner_gid)
    open(args.events_log, "wb").close()
    stop_event = threading.Event()
    listener_thread = start_listener(args, sock, listen_path, stop_event)
    _, status = os.waitpid(child, 0)
    rc = os.waitstatus_to_exitcode(status)
    finish(args, listener_thread, stop_event, rc)
    return 0 if rc == 0 else 1

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
    ap.add_argument("--jailer", help="run under this jailer binary (needs sudo)")
    ap.add_argument("--jail-uid", type=int)
    ap.add_argument("--jail-gid", type=int)
    ap.add_argument("--chroot-base", default="/srv/jailer")
    args = ap.parse_args()

    boot_args = ("console=ttyS0 reboot=k panic=1 pci=off "
                 "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd "
                 f"init={args.init_target}")
    if args.jailer:
        return main_jailed(args, boot_args)

    open(args.events_log, "wb").close()
    with tempfile.TemporaryDirectory(prefix="fc-supervisor-05-") as tmp:
        api_sock = os.path.join(tmp, "fc.sock")
        uds_prefix = os.path.join(tmp, "fc-vsock.sock")
        uds_listen = uds_prefix + "_5000"
        stop_event = threading.Event()
        listener_thread = start_listener(args, bind_listener(uds_listen), uds_listen, stop_event)
        rc = run_vmm(args, boot_args, [args.firecracker, "--api-sock", api_sock],
                     api_sock, args.kernel, args.rootfs, uds_prefix)
        finish(args, listener_thread, stop_event, rc)
        return 0 if rc == 0 else 1   # a timeout or VMM failure must not look like success

if __name__ == "__main__":
    sys.exit(main())
