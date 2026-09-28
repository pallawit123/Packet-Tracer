from scapy.all import sniff, IP, TCP, UDP
from queue import Queue
import threading

class PacketSniffer:
    def __init__(self):
        self.packet_queue = Queue()
        self.is_sniffing = False

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            
            packet_info = {
                'src': ip_src,
                'dst': ip_dst,
                'proto': proto,
                'sport': None,
                'dport': None
            }
            
            if TCP in packet:
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                packet_info['protocol'] = 'TCP'
            elif UDP in packet:
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
                packet_info['protocol'] = 'UDP'
            
            self.packet_queue.put(packet_info)

    def start_sniffing(self):
        self.is_sniffing = True
        sniff(prn=self.packet_callback, store=False)

    def stop_sniffing(self):
        self.is_sniffing = False

    def get_packets(self):
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        return packets

def run_sniffer(sniffer):
    sniffer.start_sniffing()