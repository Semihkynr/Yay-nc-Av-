from scapy.all import *
from datetime import datetime

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if ip_src == "99.181.66.84" or ip_dst == "99.181.66.84":
            log_entry = f"[{datetime.now()}] {ip_src} -> {ip_dst}\n"
            print(log_entry.strip())
            with open("trafik_log.txt", "a") as log_file:
                log_file.write(log_entry)

sniff(filter="tcp port 443", prn=packet_callback, store=0)

