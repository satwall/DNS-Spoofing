import scapy.all as scapy

def get_mac(ip):
	# generate an ARP request to get the MAC address
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	
	# Only need answered ARP reply
	arp_reply = scapy.srp(arp_request_broadcast, timeout = 5,verbose = False)[0]

#	return(arp_reply)

	macaddress = arp_reply[0][1].hwsrc

	return macaddress

