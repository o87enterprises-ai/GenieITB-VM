#!/usr/bin/env python3
"""One microVM per agent (HANDOFF_PERIMETER P2).

Each agent boots in its own Firecracker VM with its own jail, vsock socket, serial log and
receipt chain. Nothing writable is shared, and the VMs have no path to each other.

A guest can no longer see the other agents, so the group tripwire moves to the host: it
counts every line that is not on the benign list, across all VMs, and stops them together.
A separate fleet chain records the run and each VM's final chain head, so one anchor on the
fleet chain covers which VMs ran and how each chain ended.

Exit codes: 0 clean, 3 the tripwire stopped the fleet, 1 anything else.
"""
import argparse, importlib.util, os, pwd, select, sys, tempfile, threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("supervisor5", os.path.join(_HERE, "05-supervisor.py"))
sup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sup)
receipt = sup.receipt

AGENTS = (("doc", "/init-doc"), ("shell", "/init-shell"))
BENIGN = ("LSM ", "HELLO ", "ALLOW ", "TRY ", "DONE ")   # anything else counts as a denial

class PipeStop:
    """Set once the write end closes, so the VMs also stop if the fleet process dies."""
    def __init__(self, fd): self.fd = fd
    def is_set(self): return bool(select.select([self.fd], [], [], 0)[0])

class Tripwire:
    def __init__(self, db, threshold, stop_fd):
        self.db, self.threshold, self.stop_fd = db, threshold, stop_fd
        self.lock, self.denials, self.fired = threading.Lock(), 0, False

    def line(self, short, text):
        if text.startswith(BENIGN): return
        with self.lock:
            self.denials += 1
            count = self.denials
        if count >= self.threshold or text.startswith("TRIPWIRE "):
            # The guest's text is not copied here: this chain holds only host-derived facts.
            self.fire(f"TRIPWIRE denials={count} from={short} stopping fleet")

    def fire(self, detail):
        with self.lock:
            if self.fired: return
            self.fired = True
        try:
            receipt.append_run_event(self.db, "fleet", detail)
        except Exception as e:
            print(f"fleet: RECEIPT WRITE FAILED: {e}", file=sys.stderr)
        finally:
            os.close(self.stop_fd)

class VM:
    def __init__(self, args, short, init, index):
        self.short, self.init, self.jail_dir, self.pid_file = short, init, None, None
        self.after_vsock = None   # runs once Firecracker has created the vsock socket
        self.args = argparse.Namespace(**vars(args))
        prefix = f"{args.log_prefix}-{short}"
        self.args.serial_log, self.args.events_log, self.args.receipt_db = (
            f"{prefix}.log", f"{prefix}.events.log", f"{prefix}.db")
        if args.jailer:   # a VMM that escapes its VM must not share a uid with its siblings
            self.args.jail_uid = self.args.jail_gid = args.jail_uid_base + index

    def prepare_jailed(self):
        a = self.args
        self.exec_name = os.path.basename(a.firecracker)
        self.jail_id = f"genie-{os.getpid()}-{self.short}"
        self.jail_dir, root = sup.prepare_jail(a, self.jail_id)
        self.listen = os.path.join(root, sup.JAIL_UDS.lstrip("/") + "_5000")
        self.sock = sup.bind_listener(self.listen, owner=(a.jail_uid, a.jail_gid))
        self.argv, self.api = sup.jailer_argv(a, self.jail_id), os.path.join(root, sup.JAIL_API_SOCK.lstrip("/"))
        self.kernel, self.rootfs, self.uds = "/vmlinux.bin", "/rootfs.ext4", sup.JAIL_UDS
        self.pid_file = os.path.join(root, f"{self.exec_name}.pid")

    def prepare_plain(self, tmp):
        d = os.path.join(tmp, self.short); os.mkdir(d, 0o700)
        self.api, self.uds = os.path.join(d, "fc.sock"), os.path.join(d, "fc-vsock.sock")
        self.listen = self.uds + "_5000"
        self.sock = sup.bind_listener(self.listen)
        self.argv, self.kernel, self.rootfs = [self.args.firecracker, "--api-sock", self.api], self.args.kernel, self.args.rootfs

    def teardown(self):
        if self.jail_dir: sup.teardown_jail(self.jail_dir, self.exec_name, self.jail_id)

def run_child(vm, vms, read_fd, write_fd):
    rc = 1
    try:
        os.close(write_fd)
        for v in vms: v.sock.close()
        rc = sup.run_vmm(vm.args, sup.kernel_cmdline(vm.init), vm.argv, vm.api, vm.kernel, vm.rootfs,
                         vm.uds, pid_file=vm.pid_file, stop=PipeStop(read_fd),
                         after_vsock=vm.after_vsock)
    except Exception as e:
        print(f"fleet: {vm.short}: launch failed: {e}", file=sys.stderr)
        sup.dump_serial_tail(vm.args.serial_log)
    finally:
        vm.teardown()
        os._exit(rc)

def run_fleet(args, vms, drop=None, started=None, stopping=None):
    """started(trip) runs once the listeners are up. stopping() runs after every VM has
    exited and returns False if the run must fail."""
    read_fd, write_fd = os.pipe()
    for vm in vms:   # fork before any listener thread exists
        vm.pid = os.fork()
        if vm.pid == 0:
            run_child(vm, vms, read_fd, write_fd)
    os.close(read_fd)
    if drop: drop()   # everything below handles guest data

    fleet_db = args.log_prefix + ".db"
    trip = Tripwire(fleet_db, args.tripwire, write_fd)
    receipt.append_run_event(fleet_db, "fleet", f"START tripwire={args.tripwire} vms={','.join(v.short for v in vms)}")
    for vm in vms:
        open(vm.args.events_log, "wb").close()
        vm.stop_event = threading.Event()
        vm.thread = sup.start_listener(vm.args, vm.sock, vm.listen, vm.stop_event,
                                       on_line=lambda text, s=vm.short: trip.line(s, text))
    if started: started(trip)
    for vm in vms:
        _, status = os.waitpid(vm.pid, 0)
        vm.rc = os.waitstatus_to_exitcode(status)

    allowed = (0, sup.EXIT_STOPPED) if trip.fired else (0,)
    good = True
    for vm in vms:
        ok = sup.finish(vm.args, vm.thread, vm.stop_event, vm.rc)
        _, msg = receipt.verify(vm.args.receipt_db)
        receipt.append_run_event(fleet_db, "fleet", f"VM {vm.short} rc={vm.rc} chain={'OK' if ok else 'BROKEN'} {msg}")
        print(f"fleet: {vm.short} rc={vm.rc}", file=sys.stderr)
        good = good and ok and vm.rc in allowed
    if stopping: good = stopping() and good
    fleet_ok, msg = receipt.verify(fleet_db)
    print(f"fleet: fleet chain {msg} ({'OK' if fleet_ok else 'BROKEN'}) tripped={trip.fired}", file=sys.stderr)
    if not good or not fleet_ok: return 1
    return sup.EXIT_STOPPED if trip.fired else 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firecracker", required=True)
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--log-prefix", required=True, help="fleet chain is <prefix>.db, each VM uses <prefix>-<agent>.*")
    ap.add_argument("--tripwire", type=int, default=4)
    ap.add_argument("--run-timeout", type=float, default=60.0)
    ap.add_argument("--jailer")
    ap.add_argument("--jail-uid-base", type=int, default=200000, help="first of one unused uid per VM")
    ap.add_argument("--chroot-base", default="/srv/jailer")
    args = ap.parse_args()
    if args.tripwire < 1:
        ap.error("--tripwire must be at least 1")

    vms = [VM(args, short, init, i) for i, (short, init) in enumerate(AGENTS)]
    if not args.jailer:
        with tempfile.TemporaryDirectory(prefix="fc-fleet-05-") as tmp:
            for vm in vms: vm.prepare_plain(tmp)
            return run_fleet(args, vms)

    if os.geteuid() != 0 or "SUDO_UID" not in os.environ:
        print("fleet: jail mode must be started through sudo", file=sys.stderr); return 2
    if args.jail_uid_base < 1000:
        print("fleet: --jail-uid-base must be an unprivileged range", file=sys.stderr); return 2
    for vm in vms:
        try:
            print(f"fleet: uid {vm.args.jail_uid} belongs to {pwd.getpwuid(vm.args.jail_uid).pw_name}", file=sys.stderr)
            return 2
        except KeyError:
            pass   # unused, as required
    prepared = []
    try:
        for vm in vms:
            prepared.append(vm)
            vm.prepare_jailed()
    except Exception as e:
        print(f"fleet: jail setup failed: {e}", file=sys.stderr)
        for vm in prepared: vm.teardown()
        return 1
    owner = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    return run_fleet(args, vms, drop=lambda: sup.drop_privileges(*owner))

if __name__ == "__main__":
    sys.exit(main())
