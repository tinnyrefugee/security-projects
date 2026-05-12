<div align="center">

```
████████╗██╗███╗   ██╗███╗   ██╗██╗   ██╗    ██████╗ ███████╗███████╗██╗   ██╗ ██████╗ ███████╗███████╗
╚══██╔══╝██║████╗  ██║████╗  ██║╚██╗ ██╔╝    ██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝ ██╔════╝██╔════╝
   ██║   ██║██╔██╗ ██║██╔██╗ ██║ ╚████╔╝     ██████╔╝█████╗  █████╗  ██║   ██║██║  ███╗█████╗  █████╗  
   ██║   ██║██║╚██╗██║██║╚██╗██║  ╚██╔╝      ██╔══██╗██╔══╝  ██╔══╝  ██║   ██║██║   ██║██╔══╝  ██╔══╝  
   ██║   ██║██║ ╚████║██║ ╚████║   ██║       ██║  ██║███████╗██║      ╚██████╔╝╚██████╔╝███████╗███████╗
   ╚═╝   ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
```

# 🔍 Port Scanner with Banner Grabbing
### `tinny_refugee` Security Projects — Beginner Series | Project #01

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
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
- [Test Environment Setup](#-test-environment-setup)
- [Risk Port Reference](#-risk-port-reference)
- [Roadmap](#-roadmap)
- [Legal & Ethical Notice](#%EF%B8%8F-legal--ethical-notice)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 📋 Description

The **tinny_refugee Port Scanner** is a multi-threaded TCP port scanner and service fingerprinter built entirely in Python using only the standard library — no third-party dependencies required.

It was built as **Project #01** of the `tinny_refugee` public cybersecurity portfolio, with a deliberate goal: to understand reconnaissance tools at the code level, not just as black-box utilities. Most people learn to *use* Nmap. This project teaches you to understand *what Nmap is actually doing* — and proves that understanding to any interviewer, CISO, or security team lead who asks.

Port scanning is the **first phase of every professional penetration test**. Before any exploit is run, before any vulnerability is confirmed, a security professional needs a map of the target's attack surface — which ports are open, which services are listening, and what versions are exposed. This tool does exactly that.

Built by a self-taught security enthusiast, for the security community. Every line is commented. Every concept is explained. Fork it, break it, improve it.

---

## 🔧 What It Does

At its core, this tool answers three questions about any target system:

### 1. 🚪 Which doors are open?
The scanner probes a configurable range of TCP ports (default: 1–1024, extendable to 65535) using full TCP connect scans. Each port that successfully completes a connection handshake is flagged as **OPEN**.

### 2. 🏷️ What's running behind each door?
For every open port found, the scanner attempts **banner grabbing** — reading the identification string the service sends immediately after connection. This reveals the software name and version running on that port (e.g., `SSH-2.0-OpenSSH_8.4`, `220 vsFTPd 3.0.3`, `HTTP/1.1 200 OK`).

### 3. ⚠️ Which open ports are dangerous?
The scanner cross-references every open port against a built-in **risk assessment table** of historically dangerous or commonly exploited services, flagging them with human-readable CVE context (e.g., *"Port 445: SMB — EternalBlue / WannaCry vector"*).

### At the End — A Clean Report
Every scan concludes with a structured **summary report** showing target info, scan duration, all open ports mapped to service names, their banners, and any risk flags raised.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔌 **TCP Connect Scan** | Full 3-way handshake scan — most reliable open port detection method |
| 🏷️ **Banner Grabbing** | Reads service identification strings from every open port |
| ⚡ **Multi-threaded Engine** | Configurable thread count (default: 100) for fast concurrent scanning |
| 🌐 **Hostname Resolution** | Accepts both IP addresses and domain names as targets |
| 🗺️ **Service Mapping** | Maps port numbers to human-readable service names from a built-in reference table |
| ⚠️ **Risk Assessment** | Automatically flags high-risk ports (Telnet, SMB, RDP, Redis, MongoDB, etc.) with context |
| 📊 **Structured Report** | Clean, readable summary report generated after every scan |
| 🎯 **Configurable Range** | Scan any range of ports from 1 to 65535 |
| 🛡️ **Zero Dependencies** | Built entirely on Python's standard library — nothing to install beyond Python itself |
| 💻 **Cross-Platform** | Runs on Linux, macOS, and Windows |
| 🖊️ **Fully Commented** | Every function and logic block documented for learning and study |

---

## 🎯 Why You Should Try This Tool

### If you're a beginner security enthusiast:
This is the cleanest, most readable port scanner you'll find. The code is deliberately written to be *understood*, not just run. No wrappers around Nmap, no external libraries hiding the logic — just raw Python sockets doing exactly what the tool says. Read it, run it, modify it. Understanding this code means understanding the first phase of any real-world attack.

### If you're studying for a certification (CEH, OSCP, CompTIA Security+):
Port scanning and reconnaissance are core exam topics. Reading the source code of a working scanner will cement concepts that textbooks describe abstractly — TCP handshakes, service enumeration, banner grabbing — into something tangible and testable.

### If you're practicing on HackTheBox, TryHackMe, or VulnHub:
Use this as a learning tool alongside Nmap. Run both on the same target, compare results, understand why they differ. Knowing your tools at the code level is what separates candidates who pass OSCP from those who don't.

### If you're a developer who wants to understand the attacker's perspective:
You'll never build secure software until you understand how it gets attacked. This scanner shows exactly how an attacker maps your application's network exposure in seconds. That knowledge belongs in every developer's toolkit.

### If you're building your own security portfolio:
Fork this repo. Extend it. Add UDP scanning, SYN scanning, OS fingerprinting, or JSON output. Then document what you built. That's a portfolio project with depth — exactly what hiring managers and security leads want to see.

---

## 📦 Requirements

- **Python 3.8 or higher**
- No external packages — uses Python standard library only:

| Module | Purpose |
|--------|---------|
| `socket` | TCP connections and DNS resolution |
| `threading` | Concurrent port scanning |
| `queue` | Thread-safe port distribution |
| `datetime` | Scan timing and duration |
| `sys` | Input handling and exit control |

To verify your Python version:
```bash
python3 --version
```

---

## 🛠️ Installation Guide

### Option 1 — Clone the Full Portfolio Repo (Recommended)
```bash
# 1. Clone the repository
git clone https://github.com/tinny_refugee/security-projects.git

# 2. Navigate to the port scanner project
cd security-projects/beginner/01_port_scanner

# 3. Verify Python is installed
python3 --version

# 4. Run the scanner
python3 port_scanner_tinny_refugee.py
```

### Option 2 — Download Just This Script
```bash
# Using wget
wget https://raw.githubusercontent.com/tinny_refugee/security-projects/main/beginner/01_port_scanner/port_scanner_tinny_refugee.py

# OR using curl
curl -O https://raw.githubusercontent.com/tinny_refugee/security-projects/main/beginner/01_port_scanner/port_scanner_tinny_refugee.py

# Run it
python3 port_scanner_tinny_refugee.py
```

### Option 3 — Windows Users
```powershell
# Ensure Python 3.8+ is installed from https://python.org
# Open Command Prompt or PowerShell

git clone https://github.com/tinny_refugee/security-projects.git
cd security-projects\beginner\01_port_scanner
python port_scanner_tinny_refugee.py
```

### Kali Linux / Parrot OS (Pre-installed Python)
```bash
# Python 3 is already available on Kali/Parrot
# Simply clone and run — no additional setup needed
git clone https://github.com/tinny_refugee/security-projects.git
cd security-projects/beginner/01_port_scanner
python3 port_scanner_tinny_refugee.py
```

> ✅ **That's it.** No `pip install`. No virtual environments. No configuration files. Python ships with everything this tool needs.

---

## 🚀 Usage

```
python3 port_scanner_tinny_refugee.py
```

You will be prompted for:

```
  Enter target IP or hostname:  → e.g. 192.168.1.10 or scanme.nmap.org
  Start port [default 1]:       → Press Enter for default, or enter a number
  End port   [default 1024]:    → Press Enter for default, or enter a number
  Threads    [default 100]:     → Press Enter for default (recommended)
```

### Common Scan Configurations

| Scenario | Start Port | End Port | Threads | Notes |
|----------|-----------|----------|---------|-------|
| Quick top ports scan | 1 | 1024 | 100 | Covers all well-known services |
| Full port scan | 1 | 65535 | 200 | Takes longer — scan everything |
| Web services only | 80 | 8443 | 50 | HTTP, HTTPS, alternate ports |
| Database ports | 3306 | 27017 | 50 | MySQL, PostgreSQL, MongoDB, Redis |
| Single port check | 22 | 22 | 1 | Verify if SSH is open |

### Legitimate Test Targets (No Permission Needed)

| Target | Description |
|--------|-------------|
| `127.0.0.1` | Your own machine (localhost) |
| `192.168.x.x` | Your local network devices (your own only) |
| `scanme.nmap.org` | Nmap's official test server — legal to scan |
| Metasploitable 2 VM | Local lab VM — see setup below |

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║          PORT SCANNER WITH BANNER GRABBING               ║
║          Author: tinny_refugee                           ║
║          For educational and authorized use ONLY         ║
╚══════════════════════════════════════════════════════════╝

  Enter target IP or hostname: 192.168.1.10
  Start port [default 1]:    1
  End port   [default 1024]: 1024
  Threads    [default 100]:  100

  [*] Resolving 192.168.1.10...
  [*] Resolved to: 192.168.1.10
  [*] Scanning ports 1–1024 with 100 threads...

  [OPEN]  Port 21      FTP         (File Transfer Protocol)
          ↳ Banner: 220 (vsFTPd 2.3.4)
  [OPEN]  Port 22      SSH         (Secure Shell)
          ↳ Banner: SSH-2.0-OpenSSH_4.7p1
  [OPEN]  Port 23      Telnet      (Unencrypted Remote Access — DANGER)
  [OPEN]  Port 80      HTTP        (Web — Unencrypted)
          ↳ Banner: HTTP/1.1 200 OK
  [OPEN]  Port 445     SMB         (Windows Sharing — EternalBlue target)
  [OPEN]  Port 3306    MySQL       (Database)
          ↳ Banner: 5.0.51a-3ubuntu5

════════════════════════════════════════════════════════════
  SCAN REPORT — tinny_refugee
════════════════════════════════════════════════════════════
  Target   : 192.168.1.10
  Range    : Port 1 — 1024
  Duration : 4.73 seconds
  Open     : 6 port(s) found
════════════════════════════════════════════════════════════

  OPEN PORTS SUMMARY:
  PORT     SERVICE                                  BANNER
  ──────────────────────────────────────────────────────────────────────
  21       FTP  (File Transfer Protocol)            220 (vsFTPd 2.3.4)
  22       SSH  (Secure Shell)                      SSH-2.0-OpenSSH_4.7p1
  23       Telnet (Unencrypted — DANGER)            —
  80       HTTP (Web — Unencrypted)                 HTTP/1.1 200 OK
  445      SMB  (EternalBlue target)                —
  3306     MySQL (Database)                         5.0.51a-3ubuntu5

  ⚠  HIGH-RISK PORTS DETECTED:
     Port 23:  Telnet transmits credentials in PLAINTEXT
     Port 445: SMB — EternalBlue / WannaCry vector

════════════════════════════════════════════════════════════
  Scan complete. Always act ethically. — tinny_refugee
════════════════════════════════════════════════════════════
```

---

## 🔬 How It Works — Under the Hood

Understanding this section means you can explain the tool to a CISO, in a job interview, or in a write-up.

### Step 1 — DNS Resolution
Before scanning, the tool resolves the target hostname to an IP address using `socket.gethostbyname()`. This mirrors how every internet connection begins — a domain name must be translated to a routable IP address before packets can be sent.

### Step 2 — Port Queue Population
All port numbers in the requested range are added to a thread-safe `Queue`. This structure ensures each port is checked exactly once, with no duplication, even across 100 simultaneous threads.

### Step 3 — TCP Connect Scan (The Core)
Each worker thread pulls a port from the queue and attempts a **TCP three-way handshake**:

```
Scanner          Target Port
   │                  │
   │──── SYN ────────►│   "Hello, are you there?"
   │                  │
   │◄─── SYN-ACK ─────│   "Yes, I'm listening"  → PORT OPEN
   │   OR              │
   │◄─── RST ─────────│   "Nobody here"          → PORT CLOSED
   │   OR              │
   │    (timeout)      │   "No response"          → PORT FILTERED
```

`connect_ex()` returns `0` when the handshake succeeds (port open). Any other return value means closed or filtered.

### Step 4 — Banner Grabbing
For each open port, a second connection is made and the tool waits to receive the service's greeting message. The raw bytes are decoded and cleaned — only the first line is kept to avoid noise.

### Step 5 — Risk Flagging
The list of discovered open ports is checked against a hardcoded dictionary of historically risky or commonly exploited port numbers. Matches trigger warnings with plain-English CVE context.

### Step 6 — Report Generation
All results are sorted by port number and formatted into a structured summary report, including timing data and risk flags.

---

## 🧪 Test Environment Setup

> **Never scan systems you don't own or have written permission to test.**
> Use a local lab environment for all practice.

### Recommended: Metasploitable 2

Metasploitable 2 is an intentionally vulnerable Linux VM designed specifically for practicing offensive security tools. It's the perfect target for this scanner.

```bash
# Step 1: Download Metasploitable 2
# https://sourceforge.net/projects/metasploitable/

# Step 2: Import into VirtualBox or VMware
# Set network adapter to "Host-only" to isolate it from the internet

# Step 3: Boot the VM and note its IP address
# Login: msfadmin / msfadmin
# Run: ifconfig

# Step 4: Point the scanner at it
python3 port_scanner_tinny_refugee.py
# Target: [Metasploitable IP]
# Range: 1 - 1024
```

Expected result: You'll find 10–15 open ports including FTP, SSH, Telnet, HTTP, SMB, and multiple databases — a rich target for learning.

### Alternative: Scan Your Own Machine

```bash
# Scan your local machine
python3 port_scanner_tinny_refugee.py
# Target: 127.0.0.1
# Range: 1 - 65535
```

### Alternative: scanme.nmap.org

Nmap maintains a public server specifically authorized for scanning practice:
```
Target: scanme.nmap.org
```

---

## 🚨 Risk Port Reference

Ports flagged as high-risk and why:

| Port | Service | Risk |
|------|---------|------|
| **23** | Telnet | Transmits all data including passwords in **plaintext** — trivially sniffable |
| **135** | RPC | Windows Remote Procedure Call — common exploitation vector |
| **139** | NetBIOS | Legacy Windows file sharing — information leakage, brute-force target |
| **445** | SMB | EternalBlue (MS17-010) — used by WannaCry ransomware, still widely unpatched |
| **3389** | RDP | Remote Desktop — BlueKeep (CVE-2019-0708), constant brute-force target |
| **6379** | Redis | In-memory database — **often deployed with no authentication by default** |
| **27017** | MongoDB | NoSQL database — **frequently exposed to the internet unauthenticated** |

---

## 🗺️ Roadmap

Planned upgrades in future versions:

- [ ] **UDP Scanning** — Detect services running over UDP (DNS, SNMP, DHCP)
- [ ] **SYN (Stealth) Scan** — Half-open scan that doesn't complete the handshake — requires root
- [ ] **OS Fingerprinting** — Guess the target's operating system from TTL and TCP stack behavior
- [ ] **JSON / CSV Output** — Export results to file for use in reports
- [ ] **Top Ports Mode** — One-flag option to scan the 100 most commonly open ports
- [ ] **Verbose / Silent Modes** — Control how much output is shown during scan
- [ ] **CIDR Range Support** — Scan an entire subnet (e.g., `192.168.1.0/24`)

---

## ⚖️ Legal & Ethical Notice

This tool is built for **educational purposes** and **authorized security testing only**.

Scanning systems, networks, or services **without explicit written permission from the owner is illegal** in most jurisdictions, including:

- 🇺🇸 Computer Fraud and Abuse Act (CFAA) — United States
- 🇬🇧 Computer Misuse Act 1990 — United Kingdom
- 🇪🇺 Directive on Attacks Against Information Systems — European Union
- 🌍 Equivalent legislation exists in most countries worldwide

**Using this tool against systems you do not own or have written authorization to test may result in criminal prosecution.**

The author (`tinny_refugee`) accepts no responsibility for misuse of this tool. Always practice on your own systems or dedicated lab environments.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/udp-scanning`
3. Commit your changes: `git commit -m 'Add UDP scanning support'`
4. Push to the branch: `git push origin feature/udp-scanning`
5. Open a Pull Request

Please include comments explaining your changes — this repo is first and foremost a **learning resource**.

---

## 👤 Author

<div align="center">

**tinny_refugee**

*Cybersecurity Analyst | Penetration Tester | Ethical Hacker*

*Nairobi, Kenya 🇰🇪*

Building a fully public, documented cybersecurity portfolio from beginner to advanced.
One project, one write-up, one lesson at a time.

[![Medium](https://img.shields.io/badge/Medium-@tinny__refugee-black?style=for-the-badge&logo=medium)](https://medium.com/@tinny_refugee)
[![GitHub](https://img.shields.io/badge/GitHub-tinny__refugee-181717?style=for-the-badge&logo=github)](https://github.com/tinny_refugee)

> *"Security is not a product. It's a process — and understanding is the first step."*

</div>

---

## 📁 Full Portfolio Index

| # | Project | Category | Status |
|---|---------|----------|--------|
| **01** | **Port Scanner with Banner Grabbing** | Reconnaissance | ✅ **You are here** |
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

*⭐ If this helped you learn something, leave a star. It keeps the project alive.*

</div>