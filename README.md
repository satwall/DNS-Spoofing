Libraries required:

scapy

time

thread

sys

subprocess




How to use the application:

Pre-configuration
In the main.py file, you can configure the following:
	1. arp_interval - The time interval before the next ARP response gets sent out
	2. spoof_ip - The webserver's IP address which the victim will be redirected to


Start the application 

Use >> "python main.py" to start the application.

Once the application has started, it will prompt for the Target Device (Victim) IP and Gateway IP

The application will search the MAC address by using the IP addresses provided

Once the application has all of the IP and MAC addresses, it will start the ARP poisoning process which redirects traffic of the victim machine to the attacking machine.

Meanwhile, the attacking machine will sniff all the traffic on port 53.

Once the attacking machine finds any DNS query from the victim, it'll immediately send a spoofed DNS response to redirect the victim to a third party webserver. 
