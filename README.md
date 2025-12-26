# End-to-End Framework for Real-Time Network Hijack  Detection and Visualization

This project demonstrates the vulnerability of ARP in computer networks through a live ARP spoofing (Man-in-the-Middle) attack using Python and Scapy, with traffic visualized in Wireshark. 
To counter this, we implement two defenses: static ARP entries at the host level and Dynamic ARP Inspection (DAI) at the network level in Cisco Packet Tracer. 
Additionally, a simple Intrusion Detection System (IDS) is developed to detect suspicious activities such as port scans. The project bridges theory with practice, offering a clear understanding of network attacks and effective defense mechanisms.

#Motivation


ARP Spoofing is a common real-world cyber threat – it is actively used by attackers to steal sensitive information such as login credentials, financial data, and personal communications.

Many organizations and individuals are unaware of this risk, since ARP works silently in the background, making spoofing attacks hard to detect without proper monitoring.

Real-world incidents: ARP spoofing has been used in Wi-Fi hacking, corporate espionage, and even public network attacks (e.g., in cafés, airports, and hotels).

Industry Demand – Security professionals are expected to not only know theory but also demonstrate practical defenses against such attacks.

 #Research gap

Currently available network monitoring systems (Wireshark, IDS/IPS) find that they detect and log suspicious behavior but: There is usually no real-time visualization of hijack intentions:
Most systems require expert knowledge to interpret raw packet data. 
There are existing systems that focus on preventing and detecting, but not as systems that provide interactive visualization to see the change in attack flow quickly.
In the absence of sufficient visualization, the time to identify the source, target and path can be lengthy, delaying the response and mitigation opportunities. 
There are few systems built as teaching and research aids which help students conceptualize hijack scenarios in a practical visual manner.

 #Proposed Methodology

Phase 1 – Attack Simulation: Implement ARP spoofing (Man-in-the-Middle) using Python + Scapy and analyze traffic in Wireshark.
Phase 2 – Defense Mechanisms: 
Host-level: Configure static ARP entries. 
Network-level: Implement Dynamic ARP Inspection (DAI) in Cisco Packet Tracer.
Phase 3 – Detection System: Develop a simple Intrusion Detection System (IDS) to identify suspicious traffic patterns (e.g., port scans, ARP floods).
Phase 4 – Integration & Testing: Evaluate effectiveness by comparing attack success before and after defenses.

