# Basic Network Sniffer
This project is a part of my CodeAlpha internship. It involves building a network sniffer in Python that captures and analyzes network traffic.

## Overview
This network sniffer captures Ethernet frames and processes various network layer protocols including `IPv4`, `TCP`, `UDP`, and `ICMP`. The script uses raw sockets to capture packets and provides detailed information about the packets in a structured format.

## Features
**Comprehensive Packet Capture:** Captures and processes Ethernet frames and detailed information about IPv4, TCP, UDP, and ICMP packets.

**Real-Time Traffic Analysis:** Provides real-time insights into network traffic, including source and destination MAC/IP addresses, ports, and various protocol-specific details.

**Protocol Detection:** Accurately identifies and marks packets of different protocols, including HTTP traffic based on port numbers.

**Detailed Header Parsing:** Extracts and displays crucial header information:

   -    **Ethernet Header:** Source and destination MAC addresses, protocol type.
   -    **IPv4 Header:** Version, header length, TTL, protocol, source and destination IP addresses.
   -    **TCP Header:** Source and destination ports, sequence number, acknowledgment number, and flags (`URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`).
   -    **UDP Header:** Source and destination ports, length, and checksum.
   -    **ICMP Header:** Type, code, and checksum.

**User-Friendly Output:** Presents parsed data in a clear and structured format, making it easy to understand and analyze network activity.

**Error Handling:** Gracefully handles errors and interruptions, ensuring continuous and reliable packet capture.

## Requirements
`python3`
`socket library`
`struct library`
`sys library`

## Supportive Resources
To help you understand how this network sniffer works and to deepen your knowledge of networking concepts, here are some resources that were instrumental in achieving this project:
-    **TCP/IP Model:** https://www.geeksforgeeks.org/tcp-ip-model/
-    **Layers of OSI Model:**          https://www.geeksforgeeks.org/open-systems-interconnection-model-osi/
-    **What is Network Traffic?**      https://www.fortinet.com/resources/cyberglossary/network-traffic
-    **Sockets in Operating System:**  https://youtu.be/uagKTbohimU?si=UxtWhaebrlkvWH__
-    **Packet sniffer in Python:**     https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
-    **INTERNET PROTOCOL:**            https://tools.ietf.org/html/rfc791

## Note
      sudo ./Basic_Network_Sniffer.py
This script requires root privileges to access the network interface for capturing packets. Ensure you run the script with `sudo` or as the root user to avoid permission errors.
