# CodeAlpha Cybersecurity Internship — Task 1: Basic Network Sniffer

## Project Title
Basic Network Packet Sniffer (Python + Scapy)

## What This Project Is About
This project is a Python-based network packet sniffer built using Scapy. It captures live traffic on a network interface and displays the source & destination IP addresses, protocol (TCP/UDP/ICMP), ports, TCP flags, and payload data for each packet. Personally, the goal was to build hands-on experince and have an understanding of how data flows across a network at the protocol level; starting from the TCP three-way handshake, through TLS encryption negotiation, to plaintext vs. encrypted payloads — rather than just observing traffic through a pre-built GUI tool like Wireshark.

## Understanding the Concepts

### Why Packet Sniffing Matters
Every network conversation (eg loading a page or an app checking for updates) is broken into small units called packets. Being able to observe these packets is foundational to network monitoring, incident investigation, and threat detection, which is how analysts spot suspicious connections, unencrypted sensitive data, or abnormal traffic patterns.

### Why Root Privileges Are Required
I tried running the progam(without the root privilege), it brought up an error message saying "PermissionError: [Errno 1] Operation not permitted". This made me realize that operating systems restrict raw packet access by default, because an application normally only sees traffic addressed to it. Capturing *all* traffic on an interface requires bypassing this restriction (raw sockets / promiscuous mode), which is why the OS requires elevated (root) privileges to run this script. This is also why sniffers are a "dual-use" tool: the same capability used defensively (traffic monitoring) can be used offensively (credential interception on unencrypted traffic).

### Protocol Numbers
Protocol numbers in the IP header (e.g. `6` = TCP, `17` = UDP, `1` = ICMP) are standardized globally by IANA (Internet Assigned Numbers Authority), not arbitrary.

### TCP Flags and the Handshake
TCP is a connection-oriented protocol. Before real data flows, both sides perform a three-way handshake:
```
Client -> Server: SYN         (Can we talk?)
Server -> Client: SYN-ACK     (Yes, let's talk)
Client -> Server: ACK         (Confirmed, starting now)
```
Flags observed in this project: `S` (SYN), `SA` (SYN-ACK), `A` (ACK), `PA` (PSH-ACK, carries data), `FA` (FIN-ACK, graceful close). Recognizing these patterns is core to identifying scans, floods, or dropped/unreachable services in real traffic.

## Prerequisites
- Kali Linux (or any Linux distro) with Python 3
- Scapy (`sudo apt install python3-scapy`)
- Root/sudo privileges (required for raw socket access)
- A known network interface name (`ip a` to check)

## Project Files
- `sniffer.py` — the main packet sniffer script
- `README.md` — this file
- `/screenshots` — capture examples (handshake, plaintext HTTP, encrypted HTTPS, DNS)

## Step-by-Step Replication
1. Install Scapy: `sudo apt install python3-scapy -y`
2. Identify your network interface: `ip a`
3. Update the `INTERFACE` variable in `sniffer.py` to match your interface
4. Run the sniffer: `sudo python3 sniffer.py`
5. Generate traffic to observe (see Results section below for specific test commands)

## Results and Screenshots

### 1. TCP Three-Way Handshake + TLS Negotiation (HTTPS)
Captured a full HTTPS connection: SYN → SYN-ACK → ACK, followed by TLS handshake data (garbled, since TLS handshake messages are binary-formatted, not plaintext):
```
[+] 192.168.10.100 -> 150.171.22.17 | Flags: S
[+] 150.171.22.17 -> 192.168.10.100 | Flags: SA
[+] 192.168.10.100 -> 150.171.22.17 | Flags: A
[+] 192.168.10.100 -> 150.171.22.17 | Flags: PA
    Payload (bytes): [garbled — TLS handshake data]
```

### 2. Plaintext HTTP (deliberate test using neverssl.com)
Generated with `curl http://neverssl.com` to guarantee unencrypted traffic:
```
[+] 192.168.10.102 -> 34.223.124.45 | Flags: PA
    Payload (text): GET / HTTP/1.1
    Host: neverssl.com
    User-Agent: curl/8.17.0

[+] 34.223.124.45 -> 192.168.10.102 | Flags: A
    Payload (text): HTTP/1.1 200 OK
    Server: Apache/2.4.66 ()
```
Connection closed gracefully with a four-way FIN exchange: `FA` → `A` → `FA` → `A`.

### 3. Clean DNS Query/Response (UDP)
```
[+] 192.168.10.102 -> 192.168.10.1 | Protocol: UDP | Port: 54510 -> 53
[+] 192.168.10.1 -> 192.168.10.102 | Protocol: UDP | Port: 53 -> 54510
```
No handshake — confirms UDP's connectionless, "fire and forget" behavior versus TCP's connection-oriented handshake.

### 4. Real-World Diagnostic Finding
The sniffer also surfaced a live issue in my own homelab: repeated, unanswered SYN packets from a Windows VM to my Ubuntu/Splunk server on port 9997 (Splunk Universal Forwarder port):
```
[+] 192.168.10.100 -> 192.168.20.101 | TCP Port: 50040 -> 9997 | Flags: S
[+] 192.168.10.100 -> 192.168.20.101 | TCP Port: 50041 -> 9997 | Flags: S
[+] 192.168.10.100 -> 192.168.20.101 | TCP Port: 50056 -> 9997 | Flags: S
```
No SYN-ACK or RST ever returned, which confirmed that the Splunk service on the Ubuntu server was not running. This is an example signature of "port not listening" vs. "port actively refused" (which would show a fast SYN → RST-ACK exchange instead).

## Understanding the Results
- **Encrypted (HTTPS/TLS) payloads appear as garbled bytes** — this is TLS working correctly. Even with raw byte access, the actual content is unreadable without the session keys.
- **Plaintext (HTTP) payloads are fully readable** — demonstrating exactly why HTTPS adoption matters: anyone sniffing unencrypted traffic can read the full request and response.
- **Unanswered SYNs are a diagnostic signal**, not just noise — a repeated SYN with no reply indicates the destination service isn't listening, distinct from an actively refused connection (SYN → RST).

## Key Learnings (Debugging Journey)
Getting a stable capture running wasn't immediate, and the troubleshooting process was itself a valuable exercise in systematic debugging:
- **Promiscuous Mode**: The VirtualBox internal network adapter needed Promiscuous Mode set to "Allow All" before the interface would see traffic beyond what was addressed directly to the VM.
- **Socket instability**: Scapy's default libpcap-based socket intermittently failed with a vague error on this environment. ...Comparing against `tcpdump` (which worked reliably) helped isolate that the issue was Scapy-specific rather than an OS/permissions problem... Forcing `conf.use_pcap = False` (raw AF_PACKET sockets) resolved it.
- **A misleading error message**: The error `Socket failed with 'sc'. It was closed.` gave almost no detail. Wrapping the `sniff()` call in a `try/except` block with `traceback.print_exc()` was necessary to reveal the real underlying exception.
- **A real typo bug**: A misspelled keyword argument (`timwout` instead of `timeout`) caused a `TypeError` that was only visible once full tracebacks were captured, which reminded me that vague symptoms are often simple mistakes once you get the full error text instead of a truncated one.

## MITRE ATT&CK Mapping
Packet sniffing capability maps to:
- **T1040 — Network Sniffing** (Discovery / Credential Access): adversaries use sniffing to capture network traffic, potentially exposing credentials or session data sent in cleartext.

## References
- Scapy documentation: https://scapy.readthedocs.io
- IANA Protocol Numbers registry
- RFC 793 — Transmission Control Protocol

## Author
Fredrick Agufenwa
GitHub: [Phredreeq](https://github.com/Phredreeq)
LinkedIn: [fredrick-agufenwa-09bab9165](https://linkedin.com/in/fredrick-agufenwa-09bab9165)
