# PRODIGY_CS_05 Network Packet Analyzer

A network packet analyzer, often referred to as a packet sniffer or packet analyzer tool, is a software or hardware tool used to capture, analyze, and interpret network traffic. These tools are essential for network administrators, security professionals, and developers to understand and troubleshoot network communications, as well as to detect and prevent security threats.

This Python script is using the Scapy library, which is a powerful packet manipulation tool for computer networks. Let's break down the code:

  Importing Libraries: The script starts by importing the Scapy library with the alias scapy.

python

    import scapy.all as scapy

  Packet Callback Function: The packet_callback function is defined. This function is passed to the sniff function of Scapy and will be called every time a packet is captured.

  The function checks if the packet has an IP layer (scapy.IP). If it does, it extracts the source IP address (src_ip), destination IP address (dst_ip), and the protocol (protocol) from the IP layer of the packet.

  It then prints out the extracted information.

   If the packet also has a TCP layer (scapy.TCP), it tries to extract and decode the payload of the TCP packet using UTF-8 encoding. If successful, it prints "TCP Payload". If there's an error decoding or if there's no payload, it prints a corresponding message.

Similarly, if the packet has a UDP layer (scapy.UDP), it tries to extract and decode the payload of the UDP packet using UTF-8 encoding. If successful, it prints "UDP Payload". If there's an error decoding or if there's no payload, it prints a corresponding message.

python

    def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"TCP Payload")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode TCP payload.")

        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"UDP Payload")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode UDP payload.")

    Start Sniffing Function: The start_sniffing function is defined, which starts the packet sniffing process using Scapy's sniff function. It passes the packet_callback function as the callback to be invoked for each captured packet.

python

    def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)

    Start Sniffing: Finally, the script calls the start_sniffing function to begin the packet sniffing process.

python

    start_sniffing()

Overall, this script is a basic packet sniffer using Scapy that captures IP packets, extracts some information, and tries to decode and print any TCP or UDP payload it finds. It's a simple demonstration of packet analysis using Scapy.
