from scapy.all import sniff, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from collections import Counter

# Initialize counters for different protocols
protocol_counter = Counter()
service_counter = Counter()

# Function to analyze packets
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Protocol identification
        if TCP in packet:
            protocol = "TCP"
            tcp_layer = packet[TCP]
            port = tcp_layer.dport
        elif UDP in packet:
            protocol = "UDP"
            udp_layer = packet[UDP]
            port = udp_layer.dport
        elif ICMP in packet:
            protocol = "ICMP"
            port = None
        else:
            protocol = "Other"
            port = None
        
        print(f"Protocol: {protocol}")

        # Update protocol counter
        protocol_counter[protocol] += 1

        # Traffic analysis: Detect open ports and services
        if port:
            service = detect_service(port)
            if service:
                service_counter[service] += 1
                print(f"Detected Service: {service} on Port: {port}")

        # Extract metadata for specific protocols
        if protocol == "TCP":
            if port == 80:
                print(f"HTTP Packet: {packet.summary()}")
            elif port == 21:
                print(f"FTP Packet: {packet.summary()}")
            elif port == 22:
                print(f"SSH Packet: {packet.summary()}")

        print("="*40)

def detect_service(port):
    # Common ports and their services
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        53: "DNS",
        3389: "RDP",
        3306: "MySQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB"
    }
    return common_ports.get(port, None)

# Start sniffing packets
print("Starting packet capture...")
sniff(prn=packet_callback, count=100)

# Visualization: Plot the protocol distribution
protocols = list(protocol_counter.keys())
protocol_counts = list(protocol_counter.values())

plt.figure(figsize=(10, 5))
plt.bar(protocols, protocol_counts, color='blue')
plt.xlabel('Protocols')
plt.ylabel('Number of Packets')
plt.title('Network Traffic Protocol Distribution')
plt.show()

# Visualization: Plot the service distribution
services = list(service_counter.keys())
service_counts = list(service_counter.values())

plt.figure(figsize=(10, 5))
plt.bar(services, service_counts, color='green')
plt.xlabel('Services')
plt.ylabel('Number of Packets')
plt.title('Detected Services Distribution')
plt.show()

# Security insights: Highlight suspicious activities
print("\nSecurity Insights:")
for protocol, count in protocol_counter.items():
    if count > 50:
        print(f"Suspicious high number of {protocol} packets detected: {count}")

for service, count in service_counter.items():
    if count > 50:
        print(f"Suspicious high number of packets for service {service} detected: {count}")
