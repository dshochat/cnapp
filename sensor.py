#!/usr/bin/env python3
"""
sensor.py
=========
BCC / eBPF file-open sensor for CNAPP.

Attaches a kprobe to the openat(2) syscall. For every file opened by any
process it captures the PID, process name, and file path, filters down to
paths that live inside the project directory, and streams the result to
brain.py over a Unix domain socket as newline-delimited JSON.

Requirements
------------
* Linux kernel >= 4.4 with BCC installed
      sudo apt install python3-bcc        # Debian / Ubuntu
      sudo dnf install python3-bcc        # Fedora / RHEL
* Run as root, or grant CAP_BPF + CAP_SYS_ADMIN to the process
* brain.py must already be listening on SOCKET_PATH before this starts

Usage
-----
    sudo python3 sensor.py [project_dir]

    project_dir  – optional path override; defaults to the directory that
                   contains this script.
"""

import os
import sys
import json
import signal
import ctypes as ct
from typing import Optional

try:
    from bcc import BPF
except ImportError:
    sys.exit(
        "[sensor] ERROR: 'bcc' module not found.\n"
        "         Install with:  sudo apt install python3-bcc"
    )

# ── Configuration ──────────────────────────────────────────────────────────────

# Resolve to an absolute path so prefix-matching is unambiguous.
# Accept an optional CLI override (useful when sensor runs from a different cwd).
PROJECT_DIR: str = os.path.abspath(
    sys.argv[1] if len(sys.argv) > 1
    else os.path.dirname(os.path.abspath(__file__))
)

# Unix-domain socket path that brain.py listens on.
SOCKET_PATH: str = "/tmp/cnapp_brain.sock"

# ── eBPF C program ─────────────────────────────────────────────────────────────
#
# Registers for openat(int dirfd, const char *pathname, int flags, ...):
#   PARM1 → dirfd
#   PARM2 → pathname   ← we want this one
#   PARM3 → flags
#
# On kernels with CONFIG_ARCH_HAS_SYSCALL_WRAPPER (x86-64 >= 4.17) the real
# entry point __x64_sys_openat(struct pt_regs *regs) is a thin wrapper whose
# ONLY argument is a pointer to the user pt_regs.  PT_REGS_PARM2(ctx) would
# read the wrong register (the 2nd arg of the wrapper, which doesn't exist).
# We must follow PARM1 to get the inner pt_regs, then read ->si which holds
# the pathname (rsi = 2nd syscall argument in the x86-64 calling convention).
#
BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define FILENAME_LEN 256
#define COMM_LEN      16

struct event_t {
    u32  pid;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx)
{
    struct event_t ev = {};

    /*
     * __x64_sys_openat is a syscall wrapper: its only argument is a pointer
     * to the pt_regs that holds the real syscall args.
     *   PT_REGS_PARM1(ctx)  →  pointer to inner pt_regs
     *   inner_regs->si      →  rsi = pathname (2nd syscall arg)
     */
    struct pt_regs *inner_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char __user *pathname = NULL;
    bpf_probe_read_kernel(&pathname, sizeof(pathname), &inner_regs->si);

    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(ev.filename, sizeof(ev.filename), pathname);

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

# ── ctypes mirror of the BPF struct ───────────────────────────────────────────

class Event(ct.Structure):
    _fields_ = [
        ("pid",      ct.c_uint32),
        ("comm",     ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]

# ── Unix socket wrapper ────────────────────────────────────────────────────────

class BrainSocket:
    """
    Persistent Unix-domain socket connection to brain.py.

    Sends newline-delimited JSON messages and transparently reconnects once
    if the pipe breaks between events.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._sock: Optional["socket.socket"] = None  # noqa: F821

    def connect(self) -> bool:
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.connect(self._path)
            self._sock = s
            print(f"[sensor] Connected to brain.py at {self._path}")
            return True
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            print(f"[sensor] Cannot connect to brain.py: {exc}", file=sys.stderr)
            return False

    def send(self, payload: dict) -> bool:
        """
        Serialize payload as JSON and send it, terminated by a newline.
        Returns False when the connection is broken.
        """
        if self._sock is None:
            return False
        try:
            message = json.dumps(payload) + "\n"
            self._sock.sendall(message.encode("utf-8"))
            return True
        except OSError:
            self._close_socket()
            return False

    def reconnect(self) -> bool:
        self._close_socket()
        print("[sensor] Reconnecting to brain.py …", file=sys.stderr)
        return self.connect()

    def close(self) -> None:
        self._close_socket()

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[sensor] Project directory : {PROJECT_DIR}")
    print(f"[sensor] Brain socket      : {SOCKET_PATH}")

    # ── Load and attach the BPF program ───────────────────────────────────────
    bpf = BPF(text=BPF_SOURCE)
    syscall_fn = bpf.get_syscall_fnname("openat")
    bpf.attach_kprobe(event=syscall_fn, fn_name="trace_openat")
    print(f"[sensor] kprobe attached   : {syscall_fn}")

    # ── Connect to brain.py ───────────────────────────────────────────────────
    brain = BrainSocket(SOCKET_PATH)
    if not brain.connect():
        bpf.cleanup()
        sys.exit("[sensor] brain.py is not running. Start it first, then retry.")

    # ── Graceful shutdown on SIGINT / SIGTERM ─────────────────────────────────
    running = True

    def stop(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # ── Perf-buffer callback ───────────────────────────────────────────────────
    def handle_event(cpu, data, size):
        if not running:
            return

        ev = ct.cast(data, ct.POINTER(Event)).contents
        filepath = ev.filename.decode("utf-8", errors="replace")

        # Filter: only forward paths that live under the project directory.
        # We strip any trailing null bytes and check for an exact prefix match
        # so that "/path/to/project-other" is not accidentally included.
        filepath = filepath.rstrip("\x00")
        if not (filepath == PROJECT_DIR or filepath.startswith(PROJECT_DIR + "/")):
            return

        payload = {
            "pid":      ev.pid,
            "process":  ev.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            "filepath": filepath,
        }

        if not brain.send(payload):
            print("[sensor] Connection to brain.py lost.", file=sys.stderr)
            if brain.reconnect():
                brain.send(payload)  # best-effort resend of the dropped event
            else:
                print("[sensor] Reconnect failed — dropping event.", file=sys.stderr)

    # ── Poll loop ─────────────────────────────────────────────────────────────
    bpf["events"].open_perf_buffer(handle_event, page_cnt=64)
    print("[sensor] Listening for file opens. Press Ctrl-C to stop.\n")

    while running:
        try:
            bpf.perf_buffer_poll(timeout=100)   # 100 ms timeout keeps SIGINT responsive
        except KeyboardInterrupt:
            break

    print("\n[sensor] Shutting down …")
    brain.close()
    bpf.cleanup()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit(
            "[sensor] ERROR: Must be run as root.\n"
            "         eBPF requires CAP_BPF and CAP_SYS_ADMIN."
        )
    main()
