import csv
from scapy.all import sniff

# Write CSV headers once
with open("packet_log.csv", mode="w", newline="") as log_file:
    csv_writer = csv.writer(log_file)
    csv_writer.writerow(["Source IP", "Destination IP", "Protocol", "Packet Length"])

# Callback to handle each packet
def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        data = [ip_layer.src, ip_layer.dst, ip_layer.proto, len(packet)]
        print(f"[+] {data}")
        with open("packet_log.csv", mode="a", newline="") as log_file:
            csv_writer = csv.writer(log_file)
            csv_writer.writerow(data)

# Start sniffing
print("Sniffing packets... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)
