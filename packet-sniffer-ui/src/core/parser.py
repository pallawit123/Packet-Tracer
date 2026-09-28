from datetime import datetime
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether


def detect_protocol(packet: Packet) -> str:
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if IP in packet:
        return "IP"
    return "OTHER"


def packet_to_row(packet: Packet) -> dict:
    row = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src_ip": "-",
        "dst_ip": "-",
        "src_port": "-",
        "dst_port": "-",
        "protocol": detect_protocol(packet),
        "length": len(packet),
    }

    if Ether in packet:
        row["src_mac"] = packet[Ether].src
        row["dst_mac"] = packet[Ether].dst
    else:
        row["src_mac"] = "-"
        row["dst_mac"] = "-"

    if IP in packet:
        row["src_ip"] = packet[IP].src
        row["dst_ip"] = packet[IP].dst

    if TCP in packet:
        row["src_port"] = packet[TCP].sport
        row["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        row["src_port"] = packet[UDP].sport
        row["dst_port"] = packet[UDP].dport

    return row