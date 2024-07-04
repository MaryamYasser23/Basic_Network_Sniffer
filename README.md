# Basic Network Sniffer
This project is a part of my CodeAlpha internship. It involves building a network sniffer in Python that captures and analyzes network traffic.

## Overview
This network sniffer captures Ethernet frames and processes various network layer protocols including IPv4, TCP, UDP, and ICMP. The script uses raw sockets to capture packets and provides detailed information about the packets in a structured format.

## Features
**Comprehensive Packet Capture:** Captures and processes Ethernet frames and detailed information about IPv4, TCP, UDP, and ICMP packets.
**Real-Time Traffic Analysis:** Provides real-time insights into network traffic, including source and destination MAC/IP addresses, ports, and various protocol-specific details.
**Protocol Detection:** Accurately identifies and marks packets of different protocols, including HTTP traffic based on port numbers.
**Detailed Header Parsing:** Extracts and displays crucial header information:
**Ethernet Header:** Source and destination MAC addresses, protocol type.
**IPv4 Header:** Version, header length, TTL, protocol, source and destination IP addresses.
**TCP Header:** Source and destination ports, sequence number, acknowledgment number, and flags (URG, ACK, PSH, RST, SYN, FIN).
**UDP Header:** Source and destination ports, length, and checksum.
**ICMP Header:** Type, code, and checksum.
**User-Friendly Output:** Presents parsed data in a clear and structured format, making it easy to understand and analyze network activity.
**Error Handling:** Gracefully handles errors and interruptions, ensuring continuous and reliable packet capture.

## Requirements
'python3'
'socket' library
'struct' library
'sys' library

## Note
This script requires root privileges to access the network interface for capturing packets. Ensure you run the script with 'sudo' or as the root user to avoid permission errors.
