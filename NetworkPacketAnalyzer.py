# Import necessary libraries
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

# Function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer (i.e., it's an IP packet)
    if IP in packet:
        # Get source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Initialize protocol type as Unknown
        protocol = "Unknown"
        
        # Determine if the packet is TCP or UDP
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        
        # Get the current timestamp for when the packet was captured
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Display basic packet details (IP addresses, protocol)
        print(f"Time: {timestamp} | Protocol: {protocol}")
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
        
        # If the packet has a raw data payload, display it (if available)
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload: {payload[:50]}...")  # Show only the first 50 bytes for readability
        print("-" * 50)

# Main function to start the packet sniffer
def start_sniffer():
    print("Starting the packet sniffer... Press Ctrl+C to stop.")
    # Capture packets from the default network interface
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffer()
