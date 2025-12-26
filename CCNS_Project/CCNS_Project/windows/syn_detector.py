#!/usr/bin/env python3
"""
SYN Detector - Counts TCP SYN packets per source IP.
Useful for detecting possible port scans or SYN floods.
"""

import os
import pandas as pd
from collections import Counter
from datetime import datetime

# ---------------- CONFIG ----------------
if os.name == "nt":
    PCAP_FILE = r"C:\sf_shared\capture.pcap"
    OUT_FILE  = r"C:\sf_shared\syn_activity.csv"
else:
    PCAP_FILE = "/media/sf_sf_shared/capture.pcap"
    OUT_FILE  = "/media/sf_sf_shared/syn_activity.csv"

MAX_PACKETS = 10000  # adjust up to 20000 if you want deeper scanning
# ----------------------------------------

def save_df(df):
    df.to_csv(OUT_FILE, index=False)
    print(f"[+] Saved SYN activity summary to: {OUT_FILE}")
    print(df.head(15).to_string(index=False))

def analyze_with_pyshark():
    try:
        import pyshark
    except Exception as e:
        print("[!] pyshark not available:", e)
        return None

    print("[*] Reading TCP packets with pyshark from", PCAP_FILE)
    cap = None
    try:
        cap = pyshark.FileCapture(PCAP_FILE, keep_packets=False, display_filter="tcp.flags.syn==1")
    except Exception as e:
        print("[!] Error creating pyshark FileCapture:", e)
        return None

    counter = Counter()
    seen = 0
    try:
        for pkt in cap:
            seen += 1
            try:
                src = pkt.ip.src if hasattr(pkt, 'ip') else (pkt.ipv6.src if hasattr(pkt, 'ipv6') else "unknown")
                counter[src] += 1
            except Exception:
                continue
            if MAX_PACKETS and seen >= MAX_PACKETS:
                break
    finally:
        try:
            cap.close()
        except Exception:
            pass

    if not counter:
        print("[!] No SYN packets detected (pyshark path)")
        return None

    ts = datetime.now().isoformat()
    df = pd.DataFrame(list(counter.items()), columns=["src_ip", "syn_count"])
    df["timestamp"] = ts
    df["severity"] = df["syn_count"].apply(lambda x: "High" if x > 100 else "Moderate" if x > 30 else "Low")
    df.sort_values(by="syn_count", ascending=False, inplace=True)
    return df

def analyze_with_scapy():
    try:
        from scapy.all import rdpcap, TCP, IP, IPv6
    except Exception as e:
        print("[!] scapy not available:", e)
        return None

    print("[*] Reading TCP packets with scapy from", PCAP_FILE)
    try:
        packets = rdpcap(PCAP_FILE, count=MAX_PACKETS)
    except Exception as e:
        print("[!] scapy rdpcap error:", e)
        return None

    counter = Counter()
    for pkt in packets:
        try:
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                if tcp_layer.flags & 0x02:  # SYN flag
                    src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown")
                    counter[src] += 1
        except Exception:
            continue

    if not counter:
        print("[!] No SYN packets detected (scapy path)")
        return None

    ts = datetime.now().isoformat()
    df = pd.DataFrame(list(counter.items()), columns=["src_ip", "syn_count"])
    df["timestamp"] = ts
    df["severity"] = df["syn_count"].apply(lambda x: "High" if x > 100 else "Moderate" if x > 30 else "Low")
    df.sort_values(by="syn_count", ascending=False, inplace=True)
    return df

def main():
    if not os.path.exists(PCAP_FILE):
        print(f"[!] PCAP not found: {PCAP_FILE}")
        return

    df = analyze_with_pyshark()
    if df is None or df.empty:
        print("[*] Falling back to scapy-based analysis")
        df = analyze_with_scapy()

    if df is not None and not df.empty:
        save_df(df)
    else:
        print("[!] Both analyzers failed or no SYN data found.")

if __name__ == "__main__":
    main()
