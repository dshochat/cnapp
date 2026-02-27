#!/usr/bin/env python3
"""
brain.py
========
CNAPP alert correlator.

Listens on a Unix domain socket for file-open events from sensor.py,
correlates each event against vulnerability_map.json, and prints a
high-visibility alert whenever a vulnerable file is accessed.

Usage
-----
    python3 brain.py [-v] [path/to/vulnerability_map.json]

    -v   Verbose: also print a dim line for every non-vulnerable file event.
         Off by default to avoid noise.

    vulnerability_map.json defaults to the file in the same directory as
    this script.
"""

import os
import sys
import json
import signal
import socket
import threading
from datetime import datetime
from typing import Dict, List

# ── Configuration ──────────────────────────────────────────────────────────────

SOCKET_PATH   = "/tmp/cnapp_brain.sock"
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))

# Parse minimal CLI args (-v flag and optional map path)
_args    = sys.argv[1:]
VERBOSE  = "-v" in _args
_args    = [a for a in _args if a != "-v"]
MAP_PATH = os.path.abspath(_args[0]) if _args else os.path.join(SCRIPT_DIR, "vulnerability_map.json")

# ── ANSI palette ───────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"

SEVERITY_COLOR: Dict[str, str] = {
    "HIGH":   C.RED,
    "MEDIUM": C.YELLOW,
    "LOW":    C.CYAN,
}

# ── Vulnerability map ──────────────────────────────────────────────────────────

def load_vuln_map(path: str) -> Dict[str, List[dict]]:
    """
    Load vulnerability_map.json.

    Entries whose file_path is a bare filename (e.g. "server_mock.py") are
    indexed under that name.  Entries with an absolute path are indexed under
    BOTH the full path and the basename so that lookups succeed regardless of
    how the sensor reports the path.  Multiple vulns per key are preserved as
    a list.
    """
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"[brain] ERROR: vulnerability map not found → {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"[brain] ERROR: invalid JSON in vulnerability map → {exc}")

    index: Dict[str, List[dict]] = {}
    for entry in data.get("vulnerability_map", []):
        file_path = entry.get("file_path", "").strip()
        if not file_path:
            continue
        # Always index by full file_path value (bare name or absolute path)
        index.setdefault(file_path, []).append(entry)
        # Also index by basename so a full-path event matches a bare-name entry
        # and vice-versa.  Skip if basename == file_path (already added above).
        basename = os.path.basename(file_path)
        if basename != file_path:
            index.setdefault(basename, []).append(entry)

    return index

# ── Alert renderer ─────────────────────────────────────────────────────────────

_ALERT_WIDTH = 70

def _bar(color: str) -> str:
    return f"{C.BOLD}{color}{'█' * _ALERT_WIDTH}{C.RESET}"

def print_alert(event: dict, vuln: dict) -> None:
    sev   = vuln.get("severity", "UNKNOWN").upper()
    color = SEVERITY_COLOR.get(sev, C.WHITE)
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cve   = vuln.get("cve_id", "UNKNOWN")

    print(_bar(color))
    print(f"{C.BOLD}{color}  !! CNAPP ALERT  —  {cve}  !!{C.RESET}")
    print(_bar(color))
    print(f"  {C.BOLD}Time       :{C.RESET} {ts}")
    print(f"  {C.BOLD}Severity   :{C.RESET} {C.BOLD}{color}{sev}{C.RESET}")
    print(f"  {C.BOLD}CVE ID     :{C.RESET} {C.BOLD}{cve}{C.RESET}")
    print(f"  {C.BOLD}Type       :{C.RESET} {vuln.get('type', 'N/A')}")
    print(f"  {C.BOLD}File       :{C.RESET} {event.get('filepath', 'N/A')}")
    print(f"  {C.BOLD}Process    :{C.RESET} {event.get('process', '?')}  "
          f"(PID {event.get('pid', '?')})")
    print(f"  {C.BOLD}Description:{C.RESET} {vuln.get('description', 'N/A')}")
    print(_bar(color))
    print()

# ── Per-sensor connection handler ──────────────────────────────────────────────

def handle_client(conn: socket.socket, vuln_index: Dict[str, List[dict]]) -> None:
    """
    Read a stream of newline-delimited JSON events from one sensor connection
    and correlate each against the vulnerability map.
    """
    print(f"[brain] Sensor connected.")
    buf = ""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break                           # sensor disconnected cleanly
            buf += chunk.decode("utf-8", errors="replace")

            # Process every complete newline-terminated message in the buffer.
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[brain] Malformed event (ignored): {line!r}",
                          file=sys.stderr)
                    continue

                filepath = event.get("filepath", "")
                basename = os.path.basename(filepath)

                # Check both the full path and the basename so that entries
                # recorded as bare filenames still match absolute-path events
                # and vice-versa.  Deduplicate by cve_id to avoid firing the
                # same alert twice when both keys point to the same entry.
                seen: set = set()
                matches = []
                for key in (filepath, basename):
                    for vuln in vuln_index.get(key, []):
                        cve = vuln.get("cve_id", "")
                        if cve not in seen:
                            seen.add(cve)
                            matches.append(vuln)

                if matches:
                    for vuln in matches:
                        print_alert(event, vuln)
                elif VERBOSE:
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"{C.DIM}[{ts}] "
                          f"{event.get('process','?')}({event.get('pid','?')}) "
                          f"→ {filepath}{C.RESET}")

    except (ConnectionResetError, OSError):
        pass
    finally:
        conn.close()
        print("[brain] Sensor disconnected.")

# ── Unix socket server ────────────────────────────────────────────────────────

def serve(vuln_index: Dict[str, List[dict]]) -> None:
    # Clean up any stale socket file left from a previous run.
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)
    server.settimeout(1.0)      # lets the accept loop wake up to check the shutdown flag

    print(f"[brain] Listening on {SOCKET_PATH}")
    print(f"[brain] Waiting for sensor.py to connect …\n")

    running = True

    def stop(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    threads: List[threading.Thread] = []
    try:
        while running:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            t = threading.Thread(
                target=handle_client,
                args=(conn, vuln_index),
                daemon=True,
            )
            t.start()
            threads.append(t)
    finally:
        server.close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        print("\n[brain] Shut down cleanly.")

# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[brain] Loading vulnerability map: {MAP_PATH}")
    vuln_index = load_vuln_map(MAP_PATH)

    total  = sum(len(v) for v in vuln_index.values())
    files  = ", ".join(vuln_index.keys())
    print(f"[brain] {total} vulnerabilities loaded across {len(vuln_index)} file(s): {files}")
    print(f"[brain] Verbose mode: {'ON' if VERBOSE else 'OFF'}  (toggle with -v)\n")

    serve(vuln_index)


if __name__ == "__main__":
    main()
