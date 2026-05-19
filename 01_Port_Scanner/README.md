<div align="center">

```
████████╗██╗███╗   ██╗███╗   ██╗██╗   ██╗    ██████╗ ███████╗███████╗██╗   ██╗ ██████╗ ███████╗███████╗
╚══██╔══╝██║████╗  ██║████╗  ██║╚██╗ ██╔╝    ██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝ ██╔════╝██╔════╝
   ██║   ██║██╔██╗ ██║██╔██╗ ██║ ╚████╔╝     ██████╔╝█████╗  █████╗  ██║   ██║██║  ███╗█████╗  █████╗
   ██║   ██║██║╚██╗██║██║╚██╗██║  ╚██╔╝      ██╔══██╗██╔══╝  ██╔══╝  ██║   ██║██║   ██║██╔══╝  ██╔══╝
   ██║   ██║██║ ╚████║██║ ╚████║   ██║       ██║  ██║███████╗██║      ╚██████╔╝╚██████╔╝███████╗███████╗
   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
```

# 🔍 Port Scanner — Service & Version Detection
### `tinny_refugee` Security Projects — Beginner Series | Project #01

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-3.0-blueviolet?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Reconnaissance-DC143C?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Beginner-2ECC71?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Ethics](https://img.shields.io/badge/⚠%20Authorized%20Use%20Only-FF6B35?style=for-the-badge)

<br>

> *"You can't defend what you can't see. You can't attack what you don't understand."*
> — **tinny_refugee**

</div>

---

## 📖 Table of Contents

- [Description](#-description)
- [What It Does](#-what-it-does)
- [Features](#-features)
- [Why You Should Try This Tool](#-why-you-should-try-this-tool)
- [Requirements](#-requirements)
- [Installation Guide](#-installation-guide)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [How It Works — Under the Hood](#-how-it-works--under-the-hood)
- [Version Detection Coverage](#-version-detection-coverage)
- [Test Environment Setup](#-test-environment-setup)
- [Risk Port Reference](#-risk-port-reference)
- [Changelog](#-changelog)
- [Legal & Ethical Notice](#%EF%B8%8F-legal--ethical-notice)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 📋 Description

The **tinny_refugee Port Scanner** is a multi-threaded TCP port scanner with **service and version detection** — the Python equivalent of running `nmap -sV` against a target. Built entirely on Python's standard library with zero external dependencies.

It was built as **Project #01** of the `tinny_refugee` public cybersecurity portfolio with one deliberate goal: to understand reconnaissance tools at the *code level*, not just as black-box utilities. Most people learn to *use* nmap. This project teaches you to understand what nmap is actually doing — and proves that understanding to any interviewer, CISO, or security team lead who asks.

Port scanning and service fingerprinting is **Phase 1 of every professional penetration test**. Before any exploit is run, a security professional needs a complete map of the target's attack surface: which ports are open, what software is listening, what version is running, and which of those versions have known vulnerabilities. This tool produces exactly that map.

Built by a self-taught security enthusiast, for the security community. Every line is commented. Every concept is explained. Fork it, break it, improve it.

---

## 🔧 What It Does

This tool answers four critical questions about any target system:

### 1. 🚪 Which doors are open?
Probes a configurable range of TCP ports (1–65535) using full TCP Connect scans. Every port that completes a connection handshake is flagged as **OPEN**.

### 2. 🏷️ What service is running?
Maps every open port to a human-readable service name using an expanded 500+ port reference table plus an OS-level fallback (`/etc/services`). You will almost never see "Unknown Service" again.

### 3. 📌 What VERSION is running?
Sends **protocol-specific probes** to each open port and parses the responses to extract the exact software product, version number, and extra context — exactly like `nmap -sV`. Probes implemented for 16+ protocol families including SSH, FTP, HTTP, MySQL, Redis, SMB, MongoDB, and more.

### 4. ⚠️ Which findings are dangerous?
Cross-references all open ports against a risk table with CVE context, rating each finding as MEDIUM, HIGH, or CRITICAL.

### At the End — a Structured Report
Every scan produces a clean tabular report with columns for Port, Service, Product, Version, and Extra Info — the skeleton of a real recon report.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔌 **TCP Connect Scan** | Full 3-way handshake — most reliable open port detection |
| 🔬 **Version Detection** | Protocol-specific probes extract product name + version (nmap -sV equivalent) |
| 🏷️ **Service Mapping** | 500+ port reference table + OS `/etc/services` fallback |
| ⚡ **Multi-threaded Engine** | Configurable thread pool for fast concurrent scanning |
| 🌐 **Hostname Resolution** | Reverse DNS + NetBIOS name queries for Windows targets |
| ⚠️ **Risk Assessment** | CRITICAL / HIGH / MEDIUM ratings with CVE context |
| 📊 **Structured Report** | Tabular output: Port | Service | Product | Version | Extra |
| 🎯 **Configurable Range** | Scan any port range from 1 to 65535 |
| 🛡️ **Zero Dependencies** | Python standard library only — nothing to pip install |
| 💻 **Cross-Platform** | Linux, macOS, Windows |
| 🖊️ **Fully Commented** | Every function documented for learning and study |

---

## 🎯 Why You Should Try This Tool

### If you're a beginner security enthusiast
This is the cleanest, most readable port scanner + version detector you will find. No wrappers around nmap, no external libraries hiding the logic. Just raw Python sockets and regex doing exactly what the tool claims. Reading this code will cement TCP handshakes, banner grabbing, and service fingerprinting from abstract concepts into something you can explain to anyone — including a CISO.

### If you're studying for CEH, OSCP, or CompTIA Security+
Port scanning, service enumeration, and version detection are core exam and lab skills. Understanding the *code* behind these techniques rather than just the tool output puts you in a completely different tier of candidate. OSCP in particular rewards people who know what their tools are doing.

### If you're practicing on HackTheBox, TryHackMe, or VulnHub
Run this alongside nmap on every target. Compare outputs. Understand why they differ. Knowing what probe nmap sends to identify MySQL versus what we send here — that's the depth that separates people who pass OSCP from people who don't.

### If you're a developer wanting the attacker's perspective
You will never build secure software until you understand how attackers map your attack surface in seconds. This tool shows exactly that — and the version detection layer shows how much information a misconfigured service leaks just by saying hello.

### If you're building your own security portfolio
Fork this. Add UDP scanning, OS fingerprinting, JSON output, or CVE lookup integration. Every extension you build and document is a portfolio project with genuine technical depth — exactly what security hiring managers want to see.

---

## 📦 Requirements

- **Python 3.8 or higher**
- **No external packages** — uses Python standard library only:

| Module | Purpose |
|--------|---------|
| `socket` | TCP connections, DNS resolution, raw UDP |
| `threading` | Concurrent port scanning |
| `queue` | Thread-safe port distribution |
| `struct` | Binary protocol packet construction (MySQL, MongoDB, PostgreSQL, SMB) |
| `re` | Regex-based version string extraction |
| `datetime` | Scan timing |
| `sys` | Input handling |

```bash
# Verify your Python version
python3 --version   # Must be 3.8+
```

---

## 🛠️ Installation Guide

### Option 1 — Clone the Full Portfolio Repo (Recommended)
```bash
# Clone using HTTPS — works without a GitHub account
git clone https://github.com/tinny_refugee/security-projects.git

# Navigate to the port scanner
cd security-projects/beginner/01_port_scanner

# Run immediately — no pip install needed
python3 port_scanner_tinny_refugee.py
```

### Option 2 — Download Just This Script
```bash
# wget
wget https://raw.githubusercontent.com/tinny_refugee/security-projects/main/beginner/01_port_scanner/port_scanner_tinny_refugee.py

# curl
curl -O https://raw.githubusercontent.com/tinny_refugee/security-projects/main/beginner/01_port_scanner/port_scanner_tinny_refugee.py

python3 port_scanner_tinny_refugee.py
```

### Kali Linux / Parrot OS
```bash
# Python 3 ships with Kali — no setup needed
git clone https://github.com/tinny_refugee/security-projects.git
cd security-projects/beginner/01_port_scanner
python3 port_scanner_tinny_refugee.py
```

### Windows
```powershell
# Python 3.8+ from https://python.org
git clone https://github.com/tinny_refugee/security-projects.git
cd security-projects\beginner\01_port_scanner
python port_scanner_tinny_refugee.py
```

> **Troubleshooting git clone asking for credentials:**
> Public repos should never require a password. If prompted, your git credential helper may have stale data:
> ```bash
> git config --global --unset credential.helper
> git clone https://github.com/tinny_refugee/security-projects.git
> ```
> Always use the `https://` URL (not `git@github.com:`) for anonymous cloning.

---

## 🚀 Usage

```bash
python3 port_scanner_tinny_refugee.py
```

You will be prompted for:
```
  Enter target IP or hostname :  → e.g. 192.168.1.10 or scanme.nmap.org
  Start port [default 1]      :  → Press Enter for default
  End port   [default 1024]   :  → Press Enter for default
  Threads    [default 100]    :  → Press Enter for recommended default
```

### Common Scan Configurations

| Scenario | Start | End | Threads | Notes |
|----------|-------|-----|---------|-------|
| Quick standard scan | 1 | 1024 | 100 | All well-known ports |
| Full port scan | 1 | 65535 | 200 | Everything — takes longer |
| Web only | 80 | 9443 | 50 | HTTP/HTTPS and common alternates |
| Database ports | 1433 | 27017 | 30 | All major database ports |
| Single port verify | 22 | 22 | 1 | Check one specific port |

### Authorized Test Targets

| Target | Notes |
|--------|-------|
| `127.0.0.1` | Your own machine |
| `192.168.x.x` | Your own local network devices |
| `scanme.nmap.org` | Nmap's official public test server — legal to scan |
| Metasploitable 2/3 VM | Local lab — perfect test target (see setup below) |

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║    PORT SCANNER — SERVICE & VERSION DETECTION  v3.0         ║
║    Equivalent: nmap -sV target                              ║
║    Author : tinny_refugee                                   ║
║    Authorized use ONLY                                      ║
╚══════════════════════════════════════════════════════════════╝

  Enter target IP or hostname : 192.168.56.102
  Start port [default 1]    : 1
  End port   [default 1024] : 1024
  Threads    [default 100]  : 100

  [*] Resolving 192.168.56.102...
  [*] IP Address   : 192.168.56.102
  [*] Machine Name : METASPLOITABLE
  [*] Scanning 1–1024 | Threads: 100 | Mode: SV (version detection)

  [OPEN]  Port 21      FTP               vsFTPd 2.3.4
  [OPEN]  Port 22      SSH               OpenSSH 4.7p1 (protocol 2.0; Debian)
  [OPEN]  Port 23      Telnet            Telnet
  [OPEN]  Port 25      SMTP              Postfix smtpd
  [OPEN]  Port 80      HTTP              Apache httpd 2.2.8 (Ubuntu)
  [OPEN]  Port 139     NetBIOS-SSN       —
  [OPEN]  Port 445     SMB               —
  [OPEN]  Port 3306    MySQL             MySQL 5.0.51a-3ubuntu5
  [OPEN]  Port 5432    PostgreSQL        PostgreSQL (auth required)
  [OPEN]  Port 6379    Redis             Redis 2.2.12 (No authentication)

════════════════════════════════════════════════════════════════════════════════
  SCAN REPORT — tinny_refugee v3.0
════════════════════════════════════════════════════════════════════════════════
  Target Input  : 192.168.56.102
  Resolved IP   : 192.168.56.102
  Machine Name  : METASPLOITABLE
  Port Range    : 1 — 1024
  Scan Duration : 6.14 seconds
  Open Ports    : 10 found
════════════════════════════════════════════════════════════════════════════════

  PORT      SERVICE          PRODUCT              VERSION            EXTRA
  ──────────────────────────────────────────────────────────────────────────────
  21        FTP              vsFTPd               2.3.4
  22        SSH              OpenSSH              4.7p1              protocol 2.0; Debian
  23        Telnet           Telnet               —
  25        SMTP             Postfix              —                  mail.metasploitable
  80        HTTP             Apache httpd         2.2.8              Ubuntu
  139       NetBIOS-SSN      —                    —
  445       SMB              SMB                  —
  3306      MySQL            MySQL                5.0.51a-3ubuntu5
  5432      PostgreSQL       PostgreSQL           —                  auth required
  6379      Redis            Redis                2.2.12             No authentication…

  ────── RISK ASSESSMENT ───────────────────────────────────────────────────────
  !!! [CRITICAL] Port 445: SMB — EternalBlue MS17-010 / WannaCry ransomware vector
  ⚠  [HIGH]     Port 21: FTP — credentials often transmitted in plaintext
  ⚠  [HIGH]     Port 23: Telnet — ALL traffic including passwords is PLAINTEXT
  ⚠  [HIGH]     Port 3306: MySQL — direct DB access, often weak credentials
  ⚠  [HIGH]     Port 6379: Redis — frequently deployed with NO authentication

════════════════════════════════════════════════════════════════════════════════
  Scan complete. Always act ethically. — tinny_refugee
════════════════════════════════════════════════════════════════════════════════
```

---

## 🔬 How It Works — Under the Hood

### Phase 1 — TCP Connect Scan
Each worker thread pulls a port from the shared queue and attempts a **TCP three-way handshake**. `connect_ex()` returns `0` on success — the port is open. This is the same atomic operation at the heart of every port scanner, including nmap.

```
Scanner ──SYN──────────► Port
Scanner ◄──SYN-ACK────── Port   → OPEN
Scanner ──ACK──────────► Port

OR

Scanner ◄──RST─────────  Port   → CLOSED / FILTERED
```

### Phase 2 — Service Lookup
The port number is looked up in a 500+ entry reference table. If not found, `socket.getservbyport()` queries the OS's `/etc/services` database. This two-tier lookup means you will almost never see "Unknown Service".

### Phase 3 — Version Detection (The New Layer)
This is the equivalent of `nmap -sV`. A central `detect_version()` dispatcher routes each open port to its dedicated probe function:

```
detect_version(ip, port, banner)
       │
       ├── port 22  ──► probe_ssh()        → parse banner regex
       ├── port 21  ──► probe_ftp()        → parse banner regex
       ├── port 80  ──► probe_http()       → HEAD request → Server header
       ├── port 3306 ─► probe_mysql()      → raw bytes → version string
       ├── port 6379 ─► probe_redis()      → INFO command → redis_version
       ├── port 445  ─► probe_smb()        → SMBv1 negotiate → OS strings
       ├── port 5432 ─► probe_postgresql() → startup packet → auth response
       └── ... 10 more protocol handlers
```

Each probe returns a structured dict: `{product, version, extra}`.

### Phase 4 — Risk Assessment
The complete list of open ports is checked against a hardcoded risk table with severity levels (CRITICAL / HIGH / MEDIUM) and plain-English CVE context — the skeleton of a real vulnerability finding.

---

## 🔬 Version Detection Coverage

| Protocol | Port(s) | Probe Method | What We Extract |
|----------|---------|-------------|-----------------|
| **SSH** | 22, 2222 | Banner parse | Product, version, OS hint |
| **FTP** | 21, 990 | Banner regex | Product (vsFTPd/ProFTPD/etc), version |
| **SMTP** | 25, 587 | Banner + EHLO | MTA product, version, hostname |
| **HTTP** | 80, 8080+ | HEAD request | Server product (Apache/nginx/IIS), version |
| **HTTPS** | 443, 8443+ | Noted | TLS noted, sslscan recommended |
| **POP3** | 110 | Banner regex | MTA product (Dovecot/Courier/etc) |
| **IMAP** | 143 | Banner regex | MTA product, version |
| **VNC** | 5900–5903 | Banner parse | RFB protocol version |
| **MySQL** | 3306 | Raw handshake | MySQL/MariaDB version string |
| **PostgreSQL** | 5432 | Startup packet | Confirms running, auth type |
| **Redis** | 6379 | INFO command | Version, OS, mode, auth status |
| **Memcached** | 11211 | `version` cmd | Version number, auth status |
| **Elasticsearch** | 9200 | HTTP GET / | Version, Lucene version, cluster name |
| **SMB** | 445 | Negotiate pkt | Windows version strings |
| **WinRM** | 5985, 5986 | HTTP GET | Server header, Windows version |
| **MongoDB** | 27017 | OP_QUERY | Version, auth status |
| **Telnet** | 23 | Banner regex | Device type (Cisco/MikroTik/Linux) |

---

## 🧪 Test Environment Setup

> **Never scan systems you don't own or have explicit written permission to test.**

### Recommended: Metasploitable 2

Metasploitable 2 is an intentionally vulnerable Linux VM with 15+ exploitable services — the ideal target for this scanner.

```bash
# Download: https://sourceforge.net/projects/metasploitable/
# Import into VirtualBox/VMware on Host-Only network
# Boot → login: msfadmin/msfadmin → run: ifconfig → note IP

python3 port_scanner_tinny_refugee.py
# Target: [Metasploitable IP]   Range: 1–1024   Threads: 100

# Expected: FTP(21) SSH(22) Telnet(23) SMTP(25) HTTP(80)
#           MySQL(3306) PostgreSQL(5432) VNC(5900) + more
```

### Alternative: scanme.nmap.org
```
Target: scanme.nmap.org  (Nmap's authorized public test server)
```

---

## 🚨 Risk Port Reference

| Port | Service | Level | Risk |
|------|---------|-------|------|
| 445 | SMB | CRITICAL | EternalBlue MS17-010 — WannaCry ransomware attack vector |
| 1524 | Backdoor | CRITICAL | Metasploitable root shell — instant root access |
| 2375 | Docker | CRITICAL | Unauthenticated Docker daemon — full host takeover |
| 3632 | DistCC | CRITICAL | Unauthenticated remote code execution |
| 4444 | Meterpreter | CRITICAL | Metasploit listener active |
| 6200 | Backdoor | CRITICAL | Metasploitable backdoor active |
| 23 | Telnet | HIGH | All data including passwords sent in plaintext |
| 3389 | RDP | HIGH | BlueKeep CVE-2019-0708, brute-force magnet |
| 6379 | Redis | HIGH | No auth by default — database fully exposed |
| 11211 | Memcached | HIGH | No auth, DDoS amplification vector |
| 27017 | MongoDB | HIGH | No auth by default — database fully exposed |
| 9200 | Elasticsearch | HIGH | No auth, full index readable from browser |

---

## 📋 Changelog


### v2.0
- Expanded service database to 500+ ports
- Added `socket.getservbyport()` OS-level fallback
- Added reverse DNS + NetBIOS hostname resolution
- Improved banner grabbing for more protocols

### v1.0
- Initial release: TCP connect scan + basic banner grabbing
- 20-port service reference table
- Multi-threaded scanning engine

---

## ⚖️ Legal & Ethical Notice

This tool is for **educational purposes** and **authorized security testing only**.

Scanning systems without explicit written permission is illegal under:
- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act 1990
- 🇪🇺 EU Directive on Attacks Against Information Systems
- 🌍 Equivalent legislation in most countries

**The author (`tinny_refugee`) accepts no responsibility for misuse.**

---

## 🤝 Contributing

PRs welcome. Please comment your changes — this is a learning resource first.

1. Fork → `git checkout -b feature/your-feature`
2. Commit → `git commit -m 'Add UDP scanning'`
3. Push → `git push origin feature/your-feature`
4. Open Pull Request

---

## 👤 Author

<div align="center">

**tinny_refugee**
*Cybersecurity Analyst | Penetration Tester | Ethical Hacker /*

Building a fully public, documented cybersecurity portfolio — beginner to advanced.
One project. One write-up. One lesson at a time.

[![Medium](https://img.shields.io/badge/Medium-@tinny__refugee-black?style=for-the-badge&logo=medium)](https://medium.com/@tinny_refugee)
[![GitHub](https://img.shields.io/badge/GitHub-tinny__refugee-181717?style=for-the-badge&logo=github)](https://github.com/tinny_refugee)

> *"Security is not a product. It's a process — and understanding is the first step."*

</div>

---

## 📁 Full Portfolio Index

| # | Project | Category | Status |
|---|---------|----------|--------|
| **01** | **Port Scanner — Service & Version Detection** | Reconnaissance | ✅ **You are here** |
| 02 | Network Packet Sniffer | Traffic Analysis | 🔜 Coming |
| 03 | Keylogger (Research/Educational) | Malware Analysis | 🔜 Coming |
| 04 | Password Strength Analyzer + Generator | Credential Security | 🔜 Coming |
| 05 | Hash Cracker (Dictionary + Brute Force) | Credential Attacks | 🔜 Coming |
| 06 | Cryptography Tool (Fernet AES) | Encryption | 🔜 Coming |
| 07 | Subdomain Enumerator | OSINT / Recon | 🔜 Coming |
| 08 | Phishing + QR Code Detector | Threat Detection | 🔜 Coming |
| 09 | Encrypted Chat App | Secure Comms | 🔜 Coming |
| 10 | URL Shortener + Threat Intel Scan | Threat Intel | 🔜 Coming |

---

<div align="center">

*Code signed: **tinny_refugee** — Fork freely. Attribute honestly. Hack ethically.*

*⭐ If this helped you learn something, drop a star. It keeps the project going.*

</div>