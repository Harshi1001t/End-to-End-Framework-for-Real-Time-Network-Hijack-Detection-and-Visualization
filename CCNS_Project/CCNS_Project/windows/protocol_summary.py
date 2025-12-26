#!/usr/bin/env python3
"""
protocol_summary.py
Reads a capture.pcap and writes protocol summary CSV (protocol,count)

Behavior:
 - Try pyshark first (FileCapture with keep_packets=False).
 - If pyshark errors, fallback to scapy rdpcap and simple heuristic classification.
 - Limits to MAX_PACKETS for speed (adjustable).
"""

import os
import sys
from collections import Counter
import pandas as pd

# ----------------- CONFIG -----------------
# Change paths if needed (auto-detect platform)
if os.name == "nt":
    PCAP_FILE = r"C:\sf_shared\capture.pcap"
    OUT_FILE  = r"C:\sf_shared\protocol_summary.csv"
else:
    PCAP_FILE = "/media/sf_sf_shared/capture.pcap"
    OUT_FILE  = "/media/sf_sf_shared/protocol_summary.csv"

MAX_PACKETS = 5000   # maximum packets to inspect (lower for quick runs, increase for depth)
# ------------------------------------------

def save_df(df):
    try:
        df.to_csv(OUT_FILE, index=False)
        print(f"[+] Saved protocol summary to: {OUT_FILE}")
    except Exception as e:
        print("[!] Failed to save CSV:", e)

def analyze_with_pyshark(max_packets=MAX_PACKETS):
    try:
        import pyshark
    except Exception as e:
        print("[!] pyshark not available:", e)
        return None

    print("[*] Reading packets with pyshark from", PCAP_FILE)
    try:
        cap = pyshark.FileCapture(PCAP_FILE, keep_packets=False)
    except Exception as e:
        print("[!] Error creating pyshark FileCapture:", e)
        return None

    protos = []
    seen = 0
    try:
        for pkt in cap:
            seen += 1
            try:
                # highest_layer is usually a good summary (e.g., "HTTP", "DNS", "TCP")
                proto = getattr(pkt, "highest_layer", None)
                if proto:
                    protos.append(str(proto).upper())
                else:
                    # try to infer from layers list
                    layers = [l.layer_name for l in pkt.layers] if hasattr(pkt, "layers") else []
                    if layers:
                        protos.append(layers[-1].upper())
                    else:
                        protos.append("OTHER")
            except Exception:
                protos.append("OTHER")
            if max_packets and seen >= max_packets:
                break
    except KeyboardInterrupt:
        print("[!] Interrupted by user while reading pcap")
    finally:
        try:
            cap.close()
        except Exception:
            pass

    if not protos:
        print("[!] pyshark read no protocols")
        return None

    counts = Counter(protos)
    df = pd.DataFrame(list(counts.items()), columns=["protocol", "count"])
    df = df.sort_values(by="count", ascending=False).reset_index(drop=True)
    return df

def analyze_with_scapy(max_packets=MAX_PACKETS):
    try:
        from scapy.all import rdpcap, TCP, UDP, ICMP, ARP
    except Exception as e:
        print("[!] scapy not available:", e)
        return None

    print("[*] Reading packets with scapy from", PCAP_FILE)
    try:
        packets = rdpcap(PCAP_FILE, count=max_packets if max_packets else None)
    except Exception as e:
        print("[!] scapy rdpcap error:", e)
        return None

    counts = Counter()
    seen = 0
    for pkt in packets:
        seen += 1
        proto = "OTHER"
        try:
            if pkt.haslayer(ARP):
                proto = "ARP"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
            elif pkt.haslayer(TCP):
                # try to detect HTTP by payload or port
                sport = getattr(pkt.sport, '__int__', lambda: pkt.sport)()
                dport = getattr(pkt.dport, '__int__', lambda: pkt.dport)()
                if sport == 80 or dport == 80 or b"HTTP" in bytes(pkt.payload)[:20]:
                    proto = "HTTP"
                elif sport == 443 or dport == 443:
                    proto = "TLS"
                else:
                    proto = "TCP"
            elif pkt.haslayer(UDP):
                # common UDP protocols: DNS (port 53)
                sport = getattr(pkt.sport, '__int__', lambda: pkt.sport)()
                dport = getattr(pkt.dport, '__int__', lambda: pkt.dport)()
                if sport == 53 or dport == 53:
                    proto = "DNS"
                else:
                    proto = "UDP"
            else:
                proto = pkt.__class__.__name__.upper()
        except Exception:
            proto = "OTHER"
        counts[proto] += 1

    if not counts:
        print("[!] scapy read no protocols")
        return None

    df = pd.DataFrame(list(counts.items()), columns=["protocol", "count"])
    df = df.sort_values(by="count", ascending=False).reset_index(drop=True)
    return df

def main():
    if not os.path.exists(PCAP_FILE):
        print(f"[!] PCAP not found: {PCAP_FILE}")
        sys.exit(1)

    # Try pyshark (preferred)
    df = analyze_with_pyshark()
    if df is None or df.empty:
        print("[*] Falling back to scapy-based analysis")
        df = analyze_with_scapy()

    if df is None:
        print("[!] Both analyzers failed. Exiting.")
        sys.exit(1)

    # Save and show
    save_df(df)
    print(df.head(20).to_string(index=False))

if __name__ == "__main__":
    main()
