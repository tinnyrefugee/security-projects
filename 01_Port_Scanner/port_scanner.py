#!/usr/bin/env python3
"""
=============================================================
  PORT SCANNER WITH BANNER GRABBING
  Author  : tinny_refugee
  Project : Beginner Cybersecurity Portfolio — Project #1
  Purpose : Educational / Ethical Hacking Research
  WARNING : Only scan systems you own or have explicit
            written permission to test.
=============================================================

HOW IT WORKS:
-------------------------------------------------------
A port scanner works by attempting to establish a TCP connection
to each port on a target machine. If the connection succeeds,
the port is OPEN (a service is listening). If refused or it
times out, it is CLOSED or FILTERED (firewall).

Banner grabbing is the act of reading the first response a
service sends back after connection — most services announce
themselves (e.g. "SSH-2.0-OpenSSH_8.4", "220 FTP Server").
This tells us exactly WHAT is running, which we can cross-
reference against known CVEs (vulnerabilities).

This is equivalent to what happens in the Reconnaissance phase
of a pentest — BEFORE any exploit is attempted.
"""

import socket
import sys
import threading
from datetime import datetime
from queue import Queue

# ─────────────────────────────────────────────────
#  COMMON PORTS REFERENCE TABLE
#  Maps port numbers to human-readable service names
# ─────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP         (File Transfer Protocol)",
    22:   "SSH         (Secure Shell)",
    23:   "Telnet      (Unencrypted Remote Access — DANGER)",
    25:   "SMTP        (Email Sending)",
    53:   "DNS         (Domain Name System)",
    80:   "HTTP        (Web — Unencrypted)",
    110:  "POP3        (Email Receiving)",
    135:  "RPC         (Windows Remote Procedure Call)",
    139:  "NetBIOS     (Windows File Sharing)",
    143:  "IMAP        (Email Access Protocol)",
    443:  "HTTPS       (Web — Encrypted)",
    445:  "SMB         (Windows Sharing — EternalBlue target)",
    3306: "MySQL       (Database)",
    3389: "RDP         (Remote Desktop — brute-force target)",
    5432: "PostgreSQL  (Database)",
    5900: "VNC         (Remote Desktop)",
    6379: "Redis       (In-memory Database — often exposed)",
    8080: "HTTP-Alt    (Web Proxy / Dev Server)",
    8443: "HTTPS-Alt   (Alternate HTTPS)",
    27017:"MongoDB     (NoSQL Database — often unauthenticated)",
}

# ─────────────────────────────────────────────────
#  BANNER GRABBER
#  Connects to an open port and reads its greeting
# ─────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to read the service banner from an open port.
    Most services send an identification string on connect.
    Returns the banner string, or empty string if none.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services need a nudge (HTTP needs a request)
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 443 or port == 8443:
            sock.close()
            return "(HTTPS — use ssl module for banner)"

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        # Clean up the banner — take only the first line
        return banner.split("\n")[0][:80]

    except Exception:
        return ""


# ─────────────────────────────────────────────────
#  PORT SCANNER (Threaded)
#  Uses a thread pool for fast concurrent scanning
# ─────────────────────────────────────────────────

# Shared data structures for threaded scanning
open_ports   = []         # Stores (port, banner) tuples
lock         = threading.Lock()
port_queue   = Queue()


def scan_worker(ip: str, timeout: float):
    """
    Worker thread: pulls a port from the queue,
    tries to connect, grabs banner if open.
    """
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))  # Returns 0 if open
            sock.close()

            if result == 0:  # Port is OPEN
                banner = grab_banner(ip, port, timeout)
                with lock:
                    open_ports.append((port, banner))
                    service = COMMON_PORTS.get(port, "Unknown Service")
                    print(f"  [OPEN]  Port {port:<6}  {service}")
                    if banner:
                        print(f"          ↳ Banner: {banner}")

        except socket.error:
            pass
        finally:
            port_queue.task_done()


def resolve_target(target: str) -> str:
    """
    Resolve hostname to IP address.
    Explains the DNS resolution step to interviewers.
    """
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Could not resolve hostname: {target}")
        sys.exit(1)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║          PORT SCANNER WITH BANNER GRABBING               ║
║          Author: tinny_refugee                           ║
║          For educational and authorized use ONLY         ║
╚══════════════════════════════════════════════════════════╝
""")


def print_report(ip: str, target: str, start_port: int,
                 end_port: int, start_time: datetime):
    """Generate a clean summary report after scanning."""
    duration = (datetime.now() - start_time).total_seconds()

    print("\n" + "═" * 60)
    print("  SCAN REPORT — tinny_refugee")
    print("═" * 60)
    print(f"  Target   : {target} ({ip})")
    print(f"  Range    : Port {start_port} — {end_port}")
    print(f"  Duration : {duration:.2f} seconds")
    print(f"  Open     : {len(open_ports)} port(s) found")
    print("═" * 60)

    if open_ports:
        sorted_ports = sorted(open_ports, key=lambda x: x[0])
        print("\n  OPEN PORTS SUMMARY:")
        print(f"  {'PORT':<8} {'SERVICE':<40} {'BANNER'}")
        print("  " + "-" * 70)
        for port, banner in sorted_ports:
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"  {port:<8} {service:<40} {banner or '—'}")

        # Risk Assessment (this impresses CISOs)
        risky = {p for p, _ in open_ports} & {23, 135, 139, 445, 3389, 6379, 27017}
        if risky:
            print("\n  ⚠  HIGH-RISK PORTS DETECTED:")
            for p in risky:
                risk_note = {
                    23:    "Telnet transmits credentials in PLAINTEXT",
                    135:   "RPC — common attack vector on Windows",
                    139:   "NetBIOS — information leakage risk",
                    445:   "SMB — EternalBlue / WannaCry vector",
                    3389:  "RDP — brute-force / BlueKeep target",
                    6379:  "Redis — often requires NO authentication",
                    27017: "MongoDB — often exposed with no auth",
                }.get(p, "Potential risk")
                print(f"     Port {p}: {risk_note}")
    else:
        print("\n  No open ports found in the specified range.")

    print("\n" + "═" * 60)
    print("  Scan complete. Always act ethically. — tinny_refugee")
    print("═" * 60 + "\n")


# ─────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────
def main():
    print_banner()

    # ── INPUT ──────────────────────────────────────
    target = input("  Enter target IP or hostname: ").strip()
    if not target:
        print("[ERROR] No target specified.")
        sys.exit(1)

    try:
        start_port = int(input("  Start port [default 1]:    ").strip() or 1)
        end_port   = int(input("  End port   [default 1024]: ").strip() or 1024)
        threads    = int(input("  Threads    [default 100]:  ").strip() or 100)
    except ValueError:
        print("[ERROR] Ports and thread count must be integers.")
        sys.exit(1)

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("[ERROR] Port range must be between 1 and 65535.")
        sys.exit(1)

    if start_port > end_port:
        start_port, end_port = end_port, start_port  # Swap silently

    # ── RESOLVE ────────────────────────────────────
    print(f"\n  [*] Resolving {target}...")
    ip = resolve_target(target)
    print(f"  [*] Resolved to: {ip}")
    print(f"  [*] Scanning ports {start_port}–{end_port} with {threads} threads...\n")

    # ── SCAN ───────────────────────────────────────
    start_time = datetime.now()

    # Populate the queue with port numbers
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Spawn worker threads
    thread_pool = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=scan_worker, args=(ip, 1.0), daemon=True)
        t.start()
        thread_pool.append(t)

    # Wait for all threads to finish
    port_queue.join()

    # ── REPORT ─────────────────────────────────────
    print_report(ip, target, start_port, end_port, start_time)


if __name__ == "__main__":
    main()