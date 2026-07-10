"""
Basic Network Packet Sniffer
CodeAlpha Cybersecurity Internship - Task 1

Captures live network traffic on a chosen interface(mine is 'eth0') and displays:
- Source / destination IP addresses
- Protocol (TCP / UDP / ICMP)
- Source / destination ports
- TCP flags (for TCP traffic)
- Payload data (readable text where unencrypted, raw bytes otherwise)

Author: Fredrick Agufenwa
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf

# Force Scapy to use raw AF_PACKET sockets instead of libpcap.
# On this environment(kali), the libpcap-based socket intermittently failed
# with a vague "Socket failed with 'sc'. It was closed." error.
# Switching to raw sockets resolved it completely.
conf.use_pcap = False

# Map IP protocol numbers (assigned by IANA) to readable names
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


def process_packet(packet):
    """Callback function Scapy runs automatically for every captured packet."""
    if IP not in packet:
        return  # Skip non-IP traffic (eg. address resolution protocol - ARP)

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    proto_name = PROTOCOLS.get(proto_num, str(proto_num))

    print(f"[+] {src_ip} -> {dst_ip} | Protocol: {proto_name}")

    if TCP in packet:
        flags = packet[TCP].flags
        print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport} | Flags: {flags}")
    elif UDP in packet:
        print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

    if Raw in packet:
        payload = packet[Raw].load
        try:
            text = payload.decode('utf-8', errors='replace')
            print(f"    Payload (text): {text[:100]}")
        except Exception:
            print(f"    Payload (bytes): {payload[:100]}")


if __name__ == "__main__":
    INTERFACE = "eth0"   # Change this to match your own interface (check with `ip a`)
    PACKET_COUNT = 20    # Stop after this many packets
    TIMEOUT = 30          # ...or after this many seconds, whichever comes first

    print(f"Starting packet capture on {INTERFACE}... Press Ctrl+C to stop.")
    sniff(iface=INTERFACE, prn=process_packet, count=PACKET_COUNT, timeout=TIMEOUT)