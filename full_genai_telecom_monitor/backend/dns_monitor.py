from scapy.all import sniff, DNSQR, IP

def dns_sniffer():
    def process(pkt):
        if pkt.haslayer(DNSQR):
            print(f"DNS Query from {pkt[IP].src}: {pkt[DNSQR].qname.decode()}")

    sniff(filter="udp port 53", prn=process, store=False, timeout=60)