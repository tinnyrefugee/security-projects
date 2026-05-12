# security-projects
This is a collection of my security projects. Documenting my cybersecurity journey.

Here's an overview of the projects I will be doing and publishing.

<img src="SECURITY-PROJECT/Cyber-Security.jpg" alt="Cyber-Security.jpg" width="500">
---

## 📋 Project List Comparison & Final Recommendation



| # | Project | Verdict | Notes |
|---|---------|---------|-------|
| 1 | Keylogger | ✅ Keep | Great for understanding malware mechanics — frame it as "offensive research" |
| 2 | Port Scanner | ✅ Keep | Core recon tool — essential |
| 3 | Password Generator | ✅ Keep (upgrade) | Upgrade to also *analyze* password strength |
| 4 | Secure File Transfer (SFTP) | ⚠️ Swap | Too blue-team/sysadmin. Won't impress a CISO hiring a red teamer |
| 5 | Phishing Website Detector | ✅ Keep | Shows you understand the attacker's playbook |
| 6 | Encrypted Chat App | ✅ Keep | Shows crypto knowledge + networking |
| 7 | Simple Firewall | ⚠️ Move to Intermediate | More blue team. Better as an intermediate defensive project |
| 8 | Cryptography with Fernet | ✅ Keep | Solid crypto fundamentals |
| 9 | QR Code Phishing Detector | 🔀 Merge | Merge with Phishing Detector — adds depth to one project |
| 10 | URL Shortener + Threat Scan | ✅ Keep | Actually a clever OSINT/threat intel project |

### What I'd Add (Extras from the project list)

| # | Project | Why It Matters |
|---|---------|----------------|
| + | **Network Packet Sniffer** | Foundational — every pentester needs to read traffic |
| + | **Hash Cracker** (Dictionary + Brute Force) | Shows you understand credential attacks |
| + | **Subdomain Enumerator** | Recon skill — huge in bug bounty & pentesting |
| + | **Banner Grabber / Service Fingerprinter** | Ties into port scanning — shows OS/service recon |

---

## 🎯 Final Beginner Portfolio List (10 Projects)

These are ordered by logical learning progression:

```
1.  Port Scanner with Banner Grabbing         ← We start here
2.  Network Packet Sniffer (Passive)
3.  Keylogger (Ethical/Research)
4.  Password Strength Analyzer + Generator
5.  Hash Cracker (Dictionary + Brute Force)
6.  Cryptography Tool (Fernet AES Encryption)
7.  Subdomain Enumerator
8.  Phishing URL + QR Code Detector (merged)
9.  Encrypted Chat App (Python/Socket)
10. URL Shortener with Threat Intel Scan
```

This list tells a **story** to a CISO or Employer: *"I understand reconnaissance, I understand how attacks are built, and I understand how to protect against them."*

---

## 🚀 Project #1 — Port Scanner with Banner Grabbing

This is the perfect starting point. Every single pentest begins with reconnaissance, and port scanning is Step 1. A CISO will immediately recognize this as a core offensive security skill.

**What it does:**
- Scans a range of ports on a target (TCP Connect Scan)
- Grabs service banners (what software is running on each port)
- Identifies common services by port number
- Outputs a clean, readable report

**Why it impresses:** It mirrors what tools like `nmap` do under the hood. Being able to explain how it works at code level shows you aren't just a tool runner — you understand the *mechanics*.

------

## 🧠 Full Breakdown — What to Know Before the Interview

### How to Run It
```bash
python3 port_scanner_tinny_refugee.py
# Enter target: 192.168.1.1 (your router, a local VM, or a lab machine)
# Start port: 1
# End port: 1024
# Threads: 100
```
> **Always only scan machines you own or have written permission to test.** On Kali, set up a target VM (Metasploitable2 is perfect for this).

---

### The 4 Core Concepts You Can Explain to a CISO

**1. TCP Connect Scan**
> *"We attempt a full three-way handshake — SYN, SYN-ACK, ACK — on each port. If it completes, the port is open. This is the most reliable but also the most detectable method since it appears in server logs."*

**2. Banner Grabbing**
> *"After connection, most services send an identification string. SSH will say `SSH-2.0-OpenSSH_8.4`, FTP will say `220 vsftpd 3.0.3`. This tells us exactly what version is running, which I can cross-reference with CVE databases to find known vulnerabilities."*

**3. Threading**
> *"Scanning 1024 ports sequentially would take minutes. Using 100 concurrent threads, each checking a different port simultaneously, brings it down to seconds. This is the same efficiency principle tools like nmap use."*

**4. Risk Assessment Output**
> *"The scanner automatically flags high-risk ports — like 445 (SMB, the EternalBlue/WannaCry vector), 3389 (RDP, a common brute-force target), and 27017 (MongoDB, which often requires zero authentication). This is what a real initial recon report looks like."*

---

### Testing Environment (Recommended)
```bash
# Download Metasploitable2 (intentionally vulnerable VM)
# Run it in VirtualBox/VMware on your local network
# Then point the scanner at its IP — you'll find a goldmine of open ports
```

---

