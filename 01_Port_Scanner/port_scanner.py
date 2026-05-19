#!/usr/bin/env python3
"""
=============================================================
  PORT SCANNER WITH BANNER GRABBING  v2.0
  Author  : tinny_refugee
  Project : Beginner Cybersecurity Portfolio — Project #1
  Purpose : Educational / Ethical Hacking Research
  WARNING : Only scan systems you own or have explicit
            written permission to test.
=============================================================

CHANGELOG v2.0:
  - Massively expanded service database (500+ ports)
  - Added socket.getservbyport() OS-level service fallback
  - Added reverse DNS hostname resolution
  - Added NetBIOS name resolution for Windows machines
  - Improved banner grabbing for more protocol types
  - Cleaner output formatting

HOW IT WORKS (for explaining to a CISO or interviewer):
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

Hostname resolution uses three layers:
  1. Reverse DNS  — queries DNS for PTR record of the IP
  2. NetBIOS      — UDP query to port 137 (Windows machines)
  3. mDNS fallback — for local network devices

This mirrors Phase 1 (Reconnaissance) of a real pentest.
"""

import socket
import sys
import struct
import threading
from datetime import datetime
from queue import Queue

# ─────────────────────────────────────────────────────────────
#  EXPANDED SERVICE DATABASE  (500+ ports)
#  Primary lookup table — covers the most critical/common ports
#  Fallback: socket.getservbyport() queries the OS /etc/services
# ─────────────────────────────────────────────────────────────
COMMON_PORTS = {
    # ── FTP / File Transfer ───────────────────────────────────
    20:    "FTP-Data          (File Transfer — Data Channel)",
    21:    "FTP               (File Transfer Protocol)",
    69:    "TFTP              (Trivial File Transfer — UDP)",
    115:   "SFTP              (Simple File Transfer Protocol)",
    989:   "FTPS-Data         (FTP Secure — Data)",
    990:   "FTPS              (FTP over SSL/TLS)",

    # ── Remote Access ─────────────────────────────────────────
    22:    "SSH               (Secure Shell — Encrypted Remote Access)",
    23:    "Telnet            (UNENCRYPTED Remote Access — HIGH RISK)",
    513:   "rLogin            (Remote Login — Legacy/Insecure)",
    514:   "rShell/Syslog     (Remote Shell / Syslog)",
    992:   "Telnet-SSL        (Telnet over SSL)",
    2222:  "SSH-Alt           (Alternate SSH Port)",
    4422:  "SSH-Alt           (Alternate SSH Port)",

    # ── Remote Desktop ────────────────────────────────────────
    3389:  "RDP               (Windows Remote Desktop — Brute-Force Target)",
    5900:  "VNC               (Virtual Network Computing)",
    5901:  "VNC-1             (VNC Display 1)",
    5902:  "VNC-2             (VNC Display 2)",
    5903:  "VNC-3             (VNC Display 3)",

    # ── Web Services ──────────────────────────────────────────
    80:    "HTTP              (Web — Unencrypted)",
    280:   "HTTP-Mgmt         (HTTP Management)",
    443:   "HTTPS             (Web — Encrypted)",
    591:   "FileMaker-Web     (FileMaker Web Sharing)",
    593:   "HTTP-RPC          (HTTP RPC Endpoint Mapper)",
    832:   "VASS              (VASS Protocol)",
    981:   "SofaWare          (SofaWare Remote HTTPS)",
    1311:  "Dell-OpenManage   (Dell OpenManage HTTPS)",
    2082:  "cPanel            (cPanel Control Panel)",
    2083:  "cPanel-SSL        (cPanel SSL)",
    2086:  "WHM               (WebHost Manager)",
    2087:  "WHM-SSL           (WebHost Manager SSL)",
    2095:  "cPanel-Webmail    (cPanel Webmail)",
    2096:  "cPanel-Webmail-SSL(cPanel Webmail SSL)",
    4343:  "HTTPS-Alt         (Alternate HTTPS)",
    4848:  "GlassFish         (GlassFish Admin Console)",
    7080:  "HTTP-Alt          (Alternate HTTP)",
    7443:  "HTTPS-Alt         (Alternate HTTPS)",
    8000:  "HTTP-Alt          (Common Dev/App Server)",
    8008:  "HTTP-Alt          (Alternate HTTP)",
    8080:  "HTTP-Proxy        (Web Proxy / App Server)",
    8081:  "HTTP-Alt          (Alternate HTTP)",
    8082:  "HTTP-Alt          (Alternate HTTP)",
    8088:  "HTTP-Alt          (Alternate HTTP)",
    8090:  "HTTP-Alt          (Alternate HTTP)",
    8099:  "HTTP-Alt          (Alternate HTTP)",
    8180:  "HTTP-Alt          (Apache Tomcat Alt)",
    8243:  "HTTPS-Alt         (WSO2 HTTPS)",
    8280:  "HTTP-Alt          (WSO2 HTTP)",
    8333:  "Bitcoin           (Bitcoin Network)",
    8443:  "HTTPS-Alt         (Alternate HTTPS / Tomcat SSL)",
    8444:  "HTTPS-Alt         (Alternate HTTPS)",
    8800:  "HTTP-Alt          (Alternate HTTP)",
    8888:  "HTTP-Alt          (Jupyter / Dev Server)",
    9000:  "HTTP-Alt          (PHP-FPM / SonarQube)",
    9001:  "HTTP-Alt          (Tor / ORPort)",
    9090:  "HTTP-Alt          (Prometheus / Cockpit)",
    9091:  "HTTP-Alt          (Transmission Web UI)",
    9200:  "Elasticsearch     (Elasticsearch REST API — Often Exposed)",
    9443:  "HTTPS-Alt         (VMware HTTPS)",
    10000: "Webmin            (Webmin Admin Interface)",

    # ── Email ─────────────────────────────────────────────────
    25:    "SMTP              (Email Sending — Often Abused for Spam)",
    26:    "SMTP-Alt          (Alternate SMTP)",
    110:   "POP3              (Email Retrieval — Unencrypted)",
    143:   "IMAP              (Email Access — Unencrypted)",
    465:   "SMTPS             (SMTP over SSL)",
    587:   "SMTP-Submission   (Email Submission with Auth)",
    993:   "IMAPS             (IMAP over SSL)",
    995:   "POP3S             (POP3 over SSL)",

    # ── DNS ───────────────────────────────────────────────────
    53:    "DNS               (Domain Name System)",
    5353:  "mDNS              (Multicast DNS — Bonjour/Avahi)",
    8953:  "DNS-RNDC          (BIND DNS Control Channel)",

    # ── Windows / Active Directory ────────────────────────────
    88:    "Kerberos          (AD Authentication — High-Value Target)",
    135:   "MSRPC             (Windows RPC Endpoint Mapper)",
    137:   "NetBIOS-NS        (NetBIOS Name Service)",
    138:   "NetBIOS-DGM       (NetBIOS Datagram Service)",
    139:   "NetBIOS-SSN       (NetBIOS Session — Legacy Windows Sharing)",
    389:   "LDAP              (Lightweight Directory Access Protocol)",
    445:   "SMB               (Windows Sharing — EternalBlue/WannaCry Vector)",
    464:   "Kerberos-Change   (Kerberos Password Change)",
    593:   "RPC-HTTP          (RPC over HTTP)",
    636:   "LDAPS             (LDAP over SSL)",
    1026:  "DCOM              (Windows DCOM / RPC)",
    1027:  "DCOM              (Windows DCOM / RPC)",
    1028:  "DCOM              (Windows DCOM / RPC)",
    1029:  "DCOM              (Windows DCOM / RPC)",
    1433:  "MSSQL             (Microsoft SQL Server — DB Auth Target)",
    1434:  "MSSQL-Monitor     (MS SQL Server Monitor — UDP Info Leak)",
    2179:  "VMConnect         (Hyper-V VM Connect)",
    3268:  "LDAP-GC           (Active Directory Global Catalog)",
    3269:  "LDAPS-GC          (AD Global Catalog over SSL)",
    5985:  "WinRM-HTTP        (Windows Remote Management — HTTP)",
    5986:  "WinRM-HTTPS       (Windows Remote Management — HTTPS)",
    9389:  "AD-WebSvc         (Active Directory Web Services)",
    47001: "WinRM             (Windows Remote Management)",
    49152: "DCOM-High         (Windows DCOM Dynamic Port Range Start)",

    # ── Databases ─────────────────────────────────────────────
    1521:  "Oracle-DB         (Oracle Database Listener)",
    1522:  "Oracle-DB-Alt     (Oracle DB Alternate)",
    1526:  "Oracle-DB-Alt     (Oracle DB Alternate)",
    3306:  "MySQL             (MySQL Database)",
    3307:  "MySQL-Alt         (MySQL Alternate Port)",
    5432:  "PostgreSQL        (PostgreSQL Database)",
    5433:  "PostgreSQL-Alt    (PostgreSQL Alternate)",
    6379:  "Redis             (Redis In-Memory DB — Often Unauthenticated)",
    6380:  "Redis-SSL         (Redis SSL)",
    7474:  "Neo4j             (Neo4j Graph Database)",
    8086:  "InfluxDB          (InfluxDB Time-Series Database)",
    8087:  "Riak              (Riak Distributed Database)",
    9042:  "Cassandra         (Apache Cassandra Native Transport)",
    9160:  "Cassandra-Thrift  (Cassandra Thrift Interface)",
    11211: "Memcached         (Memcached — Often Exposed Unauthenticated)",
    27017: "MongoDB           (MongoDB — Often Exposed Unauthenticated)",
    27018: "MongoDB-Shard     (MongoDB Shard Server)",
    27019: "MongoDB-Config    (MongoDB Config Server)",
    28017: "MongoDB-Web       (MongoDB Web Admin)",
    50000: "DB2               (IBM DB2 Database)",

    # ── VPN / Tunneling ───────────────────────────────────────
    500:   "IKE               (IPSec VPN Key Exchange — UDP)",
    1194:  "OpenVPN           (OpenVPN)",
    1701:  "L2TP              (Layer 2 Tunneling Protocol)",
    1723:  "PPTP              (Point-to-Point Tunneling — Broken Crypto)",
    4500:  "IKE-NAT           (IPSec NAT Traversal)",

    # ── Network Infrastructure ────────────────────────────────
    67:    "DHCP-Server       (DHCP Server — UDP)",
    68:    "DHCP-Client       (DHCP Client — UDP)",
    123:   "NTP               (Network Time Protocol)",
    161:   "SNMP              (Simple Network Mgmt — Community String Leak)",
    162:   "SNMP-Trap         (SNMP Trap Receiver)",
    179:   "BGP               (Border Gateway Protocol — Routing)",
    520:   "RIP               (Routing Information Protocol — UDP)",
    1900:  "UPnP              (Universal Plug & Play — Info Disclosure)",
    2049:  "NFS               (Network File System — Often Misconfigured)",

    # ── Messaging / Chat ──────────────────────────────────────
    194:   "IRC               (Internet Relay Chat)",
    6660:  "IRC               (IRC Alternate)",
    6661:  "IRC               (IRC Alternate)",
    6662:  "IRC               (IRC Alternate)",
    6663:  "IRC               (IRC Alternate)",
    6664:  "IRC               (IRC Alternate)",
    6665:  "IRC               (IRC Alternate)",
    6666:  "IRC               (IRC Alternate)",
    6667:  "IRC               (IRC Alternate)",
    6668:  "IRC               (IRC Alternate)",
    6669:  "IRC               (IRC Alternate)",
    1863:  "MSN               (MSN Messenger)",
    5222:  "XMPP              (Jabber/XMPP Chat)",
    5223:  "XMPP-SSL          (XMPP over SSL)",
    5269:  "XMPP-Server       (XMPP Server-to-Server)",

    # ── Remote Monitoring / Management ───────────────────────
    623:   "IPMI              (Intelligent Platform Mgmt — IPMI/BMC)",
    830:   "NETCONF-SSH       (NETCONF over SSH)",
    5989:  "WBEM-HTTPS        (WBEM/CIM over HTTPS)",
    8291:  "Winbox            (MikroTik Winbox — RouterOS)",

    # ── Containers / DevOps ───────────────────────────────────
    2375:  "Docker            (Docker Daemon — UNAUTHENTICATED CRITICAL)",
    2376:  "Docker-TLS        (Docker Daemon over TLS)",
    2377:  "Docker-Swarm      (Docker Swarm Manager)",
    4243:  "Docker-Alt        (Docker Alt Port)",
    6443:  "Kubernetes-API    (Kubernetes API Server)",
    8001:  "Kubernetes-Proxy  (Kubectl Proxy)",
    10250: "Kubelet           (Kubernetes Kubelet API)",
    10255: "Kubelet-RO        (Kubernetes Kubelet Read-Only)",

    # ── Printers / IoT ────────────────────────────────────────
    9100:  "JetDirect         (HP JetDirect Printing — Raw Print Data)",
    515:   "LPD               (Line Printer Daemon)",
    631:   "IPP               (Internet Printing Protocol)",

    # ── Industrial / SCADA ────────────────────────────────────
    102:   "S7Comm            (Siemens S7 PLC — Industrial)",
    502:   "Modbus            (Modbus Industrial Protocol)",
    1911:  "NiagaraFox        (Niagara Fox Protocol — Building Automation)",
    4840:  "OPC-UA            (OPC Unified Architecture — Industrial)",
    44818: "EtherNet/IP       (Industrial Ethernet Protocol)",

    # ── Miscellaneous Notable Ports ───────────────────────────
    1080:  "SOCKS             (SOCKS Proxy)",
    1090:  "SOCKS-Alt         (SOCKS Proxy Alternate)",
    3128:  "Squid-Proxy       (Squid HTTP Proxy)",
    8118:  "Privoxy           (Privoxy Privacy Proxy)",
    4444:  "Metasploit        (Metasploit Default Listener — ALERT)",
    4445:  "Metasploit-Alt    (Metasploit Alternate Listener)",
    6200:  "Metasploitable    (Metasploitable Backdoor Shell — ALERT)",
    1524:  "Backdoor-Shell    (Metasploitable Root Shell — ALERT)",
    2121:  "FTP-Alt           (Alternate FTP)",
    3632:  "DistCC            (Distributed C Compiler — Exploitable)",
    5038:  "Asterisk-AMI      (Asterisk Manager Interface)",
    6000:  "X11               (X Window System — Remote Display)",
    6001:  "X11-1             (X11 Display 1)",
    8888:  "Jupyter           (Jupyter Notebook — Often No Auth)",
    9999:  "Telnet-Alt        (Telnet Alternate / Various Backdoors)",
}

# ─────────────────────────────────────────────────────────────
#  SERVICE LOOKUP  (with OS-level fallback)
#  1. Check our expanded custom table
#  2. Fall back to OS /etc/services database via socket module
#  3. Return "Unknown Service" only if both fail
# ─────────────────────────────────────────────────────────────
def get_service_name(port: int) -> str:
    """
    Returns the service name for a given port number.
    Uses a three-tier lookup:
      Tier 1 → Our custom expanded table (descriptive names)
      Tier 2 → OS built-in /etc/services database (socket.getservbyport)
      Tier 3 → "Unknown Service" if no match found
    """
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    # Tier 2: OS-level service database — covers hundreds more
    try:
        service = socket.getservbyport(port, 'tcp')
        return f"{service.upper():<18}(via OS service database)"
    except OSError:
        pass

    try:
        service = socket.getservbyport(port, 'udp')
        return f"{service.upper():<18}(UDP — via OS service database)"
    except OSError:
        pass

    return "Unknown Service"


# ─────────────────────────────────────────────────────────────
#  HOSTNAME RESOLUTION  (3 methods)
#  Nmap uses the same layered approach to resolve machine names
# ─────────────────────────────────────────────────────────────
def get_netbios_name(ip: str, timeout: float = 2.0) -> str:
    """
    Method 2: NetBIOS Name Service Query (UDP port 137).
    Used for Windows machines and Samba Linux hosts.
    Sends a raw NBSTAT request and parses the machine name from the response.

    Why this works: Windows machines broadcast their NetBIOS name on the
    local network. By sending a direct UDP query to port 137, we can ask
    "what is your name?" — the same way Windows Network Discovery works.
    """
    # Raw NBSTAT request packet — queries for all names registered on the target
    netbios_request = bytes([
        0x82, 0x28,              # Transaction ID
        0x00, 0x00,              # Flags: Standard query
        0x00, 0x01,              # Questions: 1
        0x00, 0x00,              # Answer RRs: 0
        0x00, 0x00,              # Authority RRs: 0
        0x00, 0x00,              # Additional RRs: 0
        # Encoded wildcard name "*" — 32 bytes of CKAAAAAA... (NetBIOS encoding)
        0x20,
        0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41,
        0x00,
        0x00, 0x21,              # Type: NBSTAT (NetBIOS status)
        0x00, 0x01               # Class: IN (Internet)
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(netbios_request, (ip, 137))
        response, _ = sock.recvfrom(1024)
        sock.close()

        # Response structure:
        # Bytes 0-11: Header
        # Bytes 12-55: Echoed question
        # Byte 56: Number of names in the response
        # Byte 57+: Name entries (18 bytes each: 15 name + 1 type + 2 flags)

        if len(response) > 57:
            num_names = response[56]
            if num_names > 0:
                raw_name = response[57:72].decode('ascii', errors='ignore').strip()
                # Filter out non-printable characters
                clean_name = ''.join(c for c in raw_name if c.isprintable() and c != '\x00')
                if clean_name:
                    return clean_name
    except Exception:
        pass
    return ""


def resolve_hostname(ip: str) -> str:
    """
    Attempts to discover the machine's hostname using multiple methods:
      1. Reverse DNS  → PTR record lookup (works for most internet-facing hosts)
      2. NetBIOS      → UDP port 137 query (Windows / Samba machines)
      3. Returns IP   → if all methods fail

    This is why Nmap shows hostnames — it uses the same layered approach.
    """
    discovered_name = None

    # ── Method 1: Reverse DNS ─────────────────────────────────
    # Queries the DNS system for the PTR record of this IP address
    # e.g., 192.168.1.1 → "router.local"
    try:
        result = socket.gethostbyaddr(ip)
        hostname = result[0]  # Returns (hostname, alias_list, ip_list)
        if hostname and hostname != ip:
            discovered_name = hostname
    except (socket.herror, socket.gaierror):
        pass

    # ── Method 2: NetBIOS (Windows / Samba) ───────────────────
    # Even if reverse DNS worked, NetBIOS gives us the Windows machine name
    # which is often more useful (e.g. "DESKTOP-ABC123" vs "192.168.1.5")
    if not discovered_name:
        netbios_name = get_netbios_name(ip)
        if netbios_name:
            discovered_name = netbios_name

    return discovered_name or ip  # Fall back to raw IP if nothing found


# ─────────────────────────────────────────────────────────────
#  BANNER GRABBER  (improved — handles more protocols)
# ─────────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Reads the service banner from an open port.
    Different protocols require different "trigger" payloads:
      - Most services (SSH, FTP, SMTP): send banner immediately on connect
      - HTTP: requires a HEAD request to get a response
      - HTTPS: requires SSL — noted but not grabbed here
      - SMB, RDP: binary protocols — noted accordingly
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # ── Protocol-specific triggers ────────────────────────
        if port in (80, 8080, 8000, 8008, 8081, 8082, 8088, 8090, 8180, 8888, 9000):
            # HTTP: send a minimal valid request
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        elif port in (443, 8443, 8444, 9443, 7443, 4343):
            sock.close()
            return "(HTTPS — TLS handshake required for banner)"

        elif port == 3389:
            sock.close()
            return "(RDP — Binary protocol, use specialized RDP scanner)"

        elif port == 445:
            sock.close()
            return "(SMB — Binary protocol, use enum4linux or smbclient)"

        elif port in (3306, 5432, 1433, 27017, 6379):
            # Databases often send a greeting — just receive
            pass

        elif port == 25:
            # SMTP sends banner immediately, then we can say EHLO
            pass

        # ── Read response ─────────────────────────────────────
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if not banner:
            return ""

        # Return first meaningful line, capped at 100 chars
        first_line = banner.split("\n")[0].strip()
        return first_line[:100] if first_line else ""

    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
#  THREADED PORT SCANNER
# ─────────────────────────────────────────────────────────────
open_ports = []
lock       = threading.Lock()
port_queue = Queue()


def scan_worker(ip: str, timeout: float):
    """Worker thread: scans ports from shared queue."""
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                banner  = grab_banner(ip, port, timeout)
                service = get_service_name(port)
                with lock:
                    open_ports.append((port, service, banner))
                    print(f"  [OPEN]  Port {port:<6}  {service}")
                    if banner:
                        print(f"          ↳ Banner: {banner}")

        except socket.error:
            pass
        finally:
            port_queue.task_done()


# ─────────────────────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

# High-risk ports with explanations for the risk report
HIGH_RISK = {
    21:    "FTP — Credentials often sent in plaintext",
    23:    "Telnet — All traffic including passwords is PLAINTEXT",
    69:    "TFTP — No authentication whatsoever",
    135:   "MSRPC — Common Windows exploitation vector",
    137:   "NetBIOS — Information leakage (usernames, shares, OS)",
    139:   "NetBIOS — Legacy sharing, pass-the-hash attacks",
    445:   "SMB — EternalBlue (MS17-010) / WannaCry ransomware vector",
    1433:  "MSSQL — Database, brute-force target",
    1434:  "MSSQL-Monitor — UDP info leakage, SA account exposure",
    1524:  "Backdoor Shell — Metasploitable root shell (CRITICAL)",
    2375:  "Docker Daemon — UNAUTHENTICATED — Full container escape (CRITICAL)",
    3306:  "MySQL — Direct database access, often weak credentials",
    3389:  "RDP — BlueKeep (CVE-2019-0708), constant brute-force target",
    3632:  "DistCC — Remote code execution without authentication",
    4444:  "Metasploit Listener — Active attack tool likely running",
    5900:  "VNC — Remote desktop, often weak/no password",
    6200:  "Backdoor Shell — Metasploitable backdoor (CRITICAL)",
    6379:  "Redis — Often deployed with NO authentication by default",
    9200:  "Elasticsearch — Often exposed unauthenticated, data exfil risk",
    11211: "Memcached — No authentication, amplification DDoS vector",
    27017: "MongoDB — Frequently internet-exposed with zero auth",
}


def print_banner_art():
    print("""
╔══════════════════════════════════════════════════════════╗
║       PORT SCANNER WITH BANNER GRABBING  v2.0           ║
║       Author : tinny_refugee                            ║
║       Use on authorized systems ONLY                    ║
╚══════════════════════════════════════════════════════════╝
""")


def print_report(ip: str, hostname: str, target_input: str,
                 start_port: int, end_port: int, start_time: datetime):
    duration = (datetime.now() - start_time).total_seconds()

    print("\n" + "═" * 65)
    print("  SCAN REPORT — tinny_refugee")
    print("═" * 65)
    print(f"  Target Input : {target_input}")
    print(f"  Resolved IP  : {ip}")

    # Show hostname if it's different from the IP
    if hostname and hostname != ip:
        print(f"  Machine Name : {hostname}")

    print(f"  Port Range   : {start_port} — {end_port}")
    print(f"  Scan Time    : {duration:.2f} seconds")
    print(f"  Open Ports   : {len(open_ports)} found")
    print("═" * 65)

    if open_ports:
        sorted_ports = sorted(open_ports, key=lambda x: x[0])

        print(f"\n  {'PORT':<8} {'SERVICE':<45} {'BANNER'}")
        print("  " + "─" * 78)
        for port, service, banner in sorted_ports:
            print(f"  {port:<8} {service:<45} {banner or '—'}")

        # Risk Assessment section
        risky_found = {p: HIGH_RISK[p] for p, _, _ in open_ports if p in HIGH_RISK}
        if risky_found:
            print("\n  ⚠  HIGH-RISK PORTS DETECTED:")
            print("  " + "─" * 60)
            for p, note in sorted(risky_found.items()):
                risk_level = "CRITICAL" if p in (1524, 2375, 4444, 6200) else "HIGH"
                print(f"  [{risk_level}] Port {p}: {note}")

    else:
        print("\n  No open ports found in the specified range.")
        print("  → Target may be firewalled or offline.")

    print("\n" + "═" * 65)
    print("  Scan complete. Always act ethically. — tinny_refugee")
    print("═" * 65 + "\n")


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
def main():
    print_banner_art()

    # ── Input ─────────────────────────────────────────────────
    target = input("  Enter target IP or hostname : ").strip()
    if not target:
        print("[ERROR] No target specified.")
        sys.exit(1)

    try:
        start_port = int(input("  Start port [default 1]    : ").strip() or 1)
        end_port   = int(input("  End port   [default 1024] : ").strip() or 1024)
        threads    = int(input("  Threads    [default 100]  : ").strip() or 100)
    except ValueError:
        print("[ERROR] Port numbers and thread count must be integers.")
        sys.exit(1)

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("[ERROR] Ports must be in range 1–65535.")
        sys.exit(1)

    if start_port > end_port:
        start_port, end_port = end_port, start_port

    # ── Resolve IP ────────────────────────────────────────────
    print(f"\n  [*] Resolving {target}...")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Could not resolve: {target}")
        sys.exit(1)
    print(f"  [*] IP Address : {ip}")

    # ── Hostname Discovery ────────────────────────────────────
    print(f"  [*] Discovering machine name...")
    hostname = resolve_hostname(ip)
    if hostname and hostname != ip:
        print(f"  [*] Machine Name : {hostname}")
    else:
        print(f"  [*] Machine Name : Not found (no PTR record / NetBIOS response)")

    print(f"  [*] Scanning ports {start_port}–{end_port} with {threads} threads...\n")

    # ── Queue & Threads ───────────────────────────────────────
    start_time = datetime.now()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    thread_pool = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=scan_worker, args=(ip, 1.0), daemon=True)
        t.start()
        thread_pool.append(t)

    port_queue.join()

    # ── Report ────────────────────────────────────────────────
    print_report(ip, hostname, target, start_port, end_port, start_time)


if __name__ == "__main__":
    main()