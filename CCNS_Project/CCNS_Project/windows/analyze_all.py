# =============================================================
# CCNS Project - Unified Analyzer (Windows Side)
# Automatically re-analyzes capture.pcap and updates all CSVs
# =============================================================

import os
import subprocess
from datetime import datetime

BASE = r"C:\sf_shared"
PCAP = os.path.join(BASE, "capture.pcap")

print("\n=== CCNS Unified Analyzer ===")
print(f"Timestamp: {datetime.now().isoformat()}")
print(f"Checking for {PCAP} ...")

if not os.path.exists(PCAP):
    print("[!] capture.pcap not found. Please run Linux demo first.")
    exit(1)

scripts = [
    ("protocol_summary", "protocol_summary.py"),
    ("http_metadata", "http_metadata.py"),
    ("syn_activity", "syn_detector.py"),
]

for name, script in scripts:
    print(f"\n[+] Running {script} ...")
    cmd = ["python", os.path.join(r"C:\CCNS_Project\windows", script)]
    try:
        subprocess.run(cmd, check=True)
        out_file = os.path.join(BASE, f"{name}.csv")
        if os.path.exists(out_file):
            print(f"[✓] {out_file} updated successfully.")
        else:
            print(f"[!] {out_file} missing after {script}.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {script} failed:", e)

print("\n=== All analyzers executed ===")
print("Now open dashboard: http://127.0.0.1:8050")
