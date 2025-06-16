from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Twitch sunucu IP'si
        if ip_src == "99.181.66.84" or ip_dst == "99.181.66.84":
            print(f"[+] Trafik: {ip_src} -> {ip_dst}")

sniff(filter="tcp port 443", prn=packet_callback, store=0)

