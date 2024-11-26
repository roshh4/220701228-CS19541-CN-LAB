from scapy.all import sniff, Ether, IP, TCP, UDP

# Packet processing function
def process_packet(packet):
    if Ether in packet:
        print(f"\nEthernet Frame: ")
        print(f"Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

    if IP in packet:
        print(f"\nIP Packet:")
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}, Protocol: {packet[IP].proto}")

    if TCP in packet:
        print(f"\nTCP Segment:")
        print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

    elif UDP in packet:
        print(f"\nUDP Segment:")
        print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

# Start sniffing packets
if __name__ == "__main__":
    print("Starting packet sniffing...")
    sniff(prn=process_packet, store=False)
