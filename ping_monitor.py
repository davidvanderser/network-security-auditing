from scapy.all import sniff, ICMP, IP

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet[ICMP].type == 8:
            print(f"[➔] PING REQUEST: {src_ip} is pinging {dst_ip}")
        elif packet[ICMP].type == 0:
            print(f"[✔] PING REPLY:   {dst_ip} responded to {src_ip}")

print("[*] Actively monitoring the NAT Network for ping traffic... Press Ctrl+C to stop.")
sniff(filter="icmp", store=0, prn=process_packet)
