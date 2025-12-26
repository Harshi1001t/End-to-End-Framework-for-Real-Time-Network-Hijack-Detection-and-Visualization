# =============================================================
# CCNS Project - HTTP Metadata Extractor
# Reads capture.pcap and extracts Host, URI, User-Agent
# =============================================================

import pyshark
import pandas as pd
import os
from datetime import datetime

PCAP_FILE = r"C:\sf_shared\capture.pcap"
OUT_FILE = r"C:\sf_shared\http_metadata.csv"

def extract_http_metadata():
    if not os.path.exists(PCAP_FILE):
        print(f"[!] File not found: {PCAP_FILE}")
        return

    print(f"[*] Reading packets from {PCAP_FILE} ...")

    cap = pyshark.FileCapture(PCAP_FILE, display_filter="http", keep_packets=False)

    data = []
    for pkt in cap:
        try:
            ts = datetime.fromtimestamp(float(pkt.sniff_timestamp))
            src = pkt.ip.src if hasattr(pkt, 'ip') else (pkt.ipv6.src if hasattr(pkt, 'ipv6') else 'N/A')
            dst = pkt.ip.dst if hasattr(pkt, 'ip') else (pkt.ipv6.dst if hasattr(pkt, 'ipv6') else 'N/A')
            host = getattr(pkt.http, 'host', 'N/A')
            uri = getattr(pkt.http, 'request_uri', '/')
            agent = getattr(pkt.http, 'user_agent', 'N/A')
            data.append([ts.isoformat(), src, dst, host, uri, agent])
        except Exception:
            continue

    cap.close()

    if not data:
        print("[!] No HTTP packets found.")
        return

    df = pd.DataFrame(data, columns=["timestamp", "src", "dst", "host", "uri", "user_agent"])
    df.to_csv(OUT_FILE, index=False)
    print(f"[+] Saved HTTP metadata to: {OUT_FILE}")
    print(df.head())

if __name__ == "__main__":
    extract_http_metadata()
