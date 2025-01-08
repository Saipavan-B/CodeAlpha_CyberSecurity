from scapy.all import sniff, IP, TCP, UDP

# Callback function to process each captured packet
def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        ip_layer = packet[IP]
        print(f"\nSource IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        # Analyze transport layer protocols
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")
        else:
            print("Protocol: Other")

# Start sniffing network packets
print("Starting network sniffer...")
sniff(filter="ip", prn=packet_callback, store=0)
