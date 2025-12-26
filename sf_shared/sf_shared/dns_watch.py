#!/usr/bin/env python3
from scapy.all import sniff, DNS, DNSRR
from collections import defaultdict
import csv, os
from datetime import datetime

SHARED_DIR = "/media/sf_sf_shared"
ALERT_FILE = os.path.join(SHARED_DIR, "alerts.csv")
MONITOR_DOMAINS = {"google.com","example.com"}

domain_seen = defaultdict(set)

if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp","type","ip_or_domain","details"])

def log_alert(alert_type, domain, details=""):
    ts = datetime.utcnow().isoformat()
    with open(ALERT_FILE, "a", newline="") as f:
        csv.writer(f).writerow([ts, alert_type, domain, details])
    print(f"[DNS ALERT] {ts} {alert_type} {domain} {details}")

def handle(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
        dns = pkt.getlayer(DNS)
        qname = dns.qd.qname.decode().rstrip(".") if dns.qd else None
        if not qname or not any(qname.endswith(dm) for dm in MONITOR_DOMAINS):
            return
        answers = [rr.rdata for rr in dns.an if isinstance(rr, DNSRR) and rr.type == 1]
        new_set, prev = set(map(str, answers)), domain_seen.get(qname, set())
        if prev and new_set != prev:
            log_alert("DNS_CHANGE", qname, f"prev:{';'.join(prev)} new:{';'.join(new_set)}")
        domain_seen[qname] = new_set

print("[*] Starting DNS watch (Ctrl+C to stop)")
try:
    sniff(filter="udp port 53", prn=handle, store=0)
except KeyboardInterrupt:
    print("[*] DNS watch stopped.")
