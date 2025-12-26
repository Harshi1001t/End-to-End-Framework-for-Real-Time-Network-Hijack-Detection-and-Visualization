#!/usr/bin/env python3
from scapy.all import sniff, ARP, wrpcap
import csv, os
from datetime import datetime
from collections import defaultdict

SHARED_DIR = "/media/sf_sf_shared"
ALERT_FILE = os.path.join(SHARED_DIR, "alerts.csv")
SUSPICIOUS_PCAP = os.path.join(SHARED_DIR, "suspicious_arp.pcap")

ip_mac = defaultdict(set)
suspicious_packets = []

if not os.path.exists(SHARED_DIR):
    os.makedirs(SHARED_DIR, exist_ok=True)

if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp","type","ip_or_domain","details"])

def log_alert(alert_type, target, details=""):
    ts = datetime.utcnow().isoformat()
    with open(ALERT_FILE, "a", newline="") as f:
        csv.writer(f).writerow([ts, alert_type, target, details])
    print(f"[ALERT] {ts} {alert_type} {target} {details}")

def handle(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2):
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        ip_mac[ip].add(mac)
        if len(ip_mac[ip]) > 1:
            log_alert("ARP_SPOOF_SUSPECT", ip, f"MACs:{';'.join(ip_mac[ip])}")
            suspicious_packets.append(pkt)
        if pkt[ARP].op == 2 and pkt[ARP].psrc == pkt[ARP].pdst:
            log_alert("GRATUITOUS_ARP", ip, f"mac:{mac}")
            suspicious_packets.append(pkt)

print("[*] Starting ARP monitor (Ctrl+C to stop)")
try:
    sniff(filter="arp", prn=handle, store=0)
except KeyboardInterrupt:
    if suspicious_packets:
        wrpcap(SUSPICIOUS_PCAP, suspicious_packets)
        print(f"Saved suspicious packets to {SUSPICIOUS_PCAP}")
    else:
        print("No suspicious ARP packets recorded.")
