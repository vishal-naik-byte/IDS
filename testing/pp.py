from scapy.all import sniff, TCP, UDP, IP, Raw
import re

# List of malicious signatures (for demonstration purposes)
# Format: {'signature_type': 'pattern'}
malicious_signatures = [
    {'type': 'IP', 'pattern': '192.168.1.100'},  # Example malicious IP
    {'type': 'PORT', 'pattern': 80},             # Example malicious port
    {'type': 'PAYLOAD', 'pattern': r"select.*from.*users"},  # Example SQL Injection pattern
]

def match_signature(packet):
    """Check if a packet matches any predefined malicious signature."""
    for sig in malicious_signatures:
        if sig['type'] == 'IP':
            # Match based on source or destination IP address
            if packet[IP].src == sig['pattern'] or packet[IP].dst == sig['pattern']:
                return True, f"Malicious IP match: {sig['pattern']}"
        
        elif sig['type'] == 'PORT':
            # Match based on destination port (TCP/UDP)
            if TCP in packet and packet[TCP].dport == sig['pattern']:
                return True, f"Malicious port match: {sig['pattern']}"
            elif UDP in packet and packet[UDP].dport == sig['pattern']:
                return True, f"Malicious port match: {sig['pattern']}"

        elif sig['type'] == 'PAYLOAD':
            # Match based on payload content using regex (e.g., SQL injection patterns)
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                if re.search(sig['pattern'], payload):
                    return True, f"Malicious payload match: {sig['pattern']}"

    return False, None

def packet_callback(packet,gui_instance):
    """Callback function to process each packet."""
    try:
        # Only process IP packets (skip non-IP packets like ARP, etc.)
        if IP in packet:
            # Check packet against malicious signatures
            is_malicious, message = match_signature(packet)
            if is_malicious:
                print(f"[ALERT] {message}")
            else:
                print(f"Packet OK: {packet[IP].src} -> {packet[IP].dst}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Capture packets on the network interface (e.g., eth0)
def main():
    print("Starting NIDS...")
    sniff(prn=packet_callback, store=0, iface="wlan0")

if __name__ == "__main__":
    main()
