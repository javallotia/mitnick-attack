# Detect ARP Spoof Attack Using Scapy

import scapy.all as scapy
from python_arptable import ARPTABLE

# GET MAC Address
def mac(ipadd):

	# Send arp packet requests from the IP address and throw an error if it's wrong
	arp_request = scapy.ARP(pdst=ipadd)
	br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_br = br / arp_request
	list1 = scapy.srp(arp_request_br, timeout=5,verbose=False)[0]
	return list1[0][1].hwsrc

# System Interface (br-..) as an argument to sniff packets inside the network
def sniff(interface):
	
	myFilter = "tcp and src host 10.0.2.10 and dst 10.0.2.8"
	# To discard sniffed packets used store=False
	scapy.sniff(iface=interface,filter=myFilter, store=False,prn=process_sniffed_pkt)


# Check and process sniffed packets
def process_sniffed_pkt(pkt):
	print(pkt.show())
	mac_server = None
	
	for arp in ARPTABLE:
		if arp['IP address'] == packet[scapy.IP].src:
			mac_server = arp['HW address']
        
	if pkt[scapy.Ether].src != mac_server:
		print(pkt[scapy.Ether].src)
		print(mac_server)
		print('Detected a Spoof attack from ' + str(pkt[scapy.Ether].src) + ' MAC address')
		print('The system is compromised by this attacker and vulnerable to remote shell!!!')
	else:
		print('Packet received from Trusted server')

# machine interface is "eth0", sniffing the interface
sniff("eth0")