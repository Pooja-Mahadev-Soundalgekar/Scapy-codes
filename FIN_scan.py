import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys
import socket

def sniffPackets(packet):
	if packet.haslayer(IP):
		pckt_src=packet[IP].src
		pckt_dst=packet[IP].dst
		pckt_ttl=packet[IP].ttl
		print "Packet: %s is going to %s and has ttl value %s" % (pckt_src,pckt_dst,pckt_ttl)

hostname = sys.argv[1]
portlist=[]
ip1=hostname.split("/")
ip = socket.gethostbyname(ip1[0])

print ip,"\n"
if len(sys.argv) ==2:
		start= 0
		end= 1023
		for i in range(start,end+1):
			portlist.append(i)
if len(sys.argv) ==4:
	start = int(sys.argv[2])
	end = int(sys.argv[3])
	for i in range(start,end+1):
			portlist.append(i)
if len(sys.argv) ==5:
	start = int(sys.argv[2])
	end = int(sys.argv[3])
	extra =sys.argv[4]
	for i in range(start,end+1):
			portlist.append(i)
if len(sys.argv) ==3:
	port=sys.argv[2]
	ports=port.split(",")
	portlist=ports

if len(ip1)== 2:
	ans, unans = sr(IP(dst=hostname)/TCP(dport=(start,end),flags='F'),timeout=1) 
	for s,r in ans:
		    if s[TCP].dport==r[TCP].sport:
		       print str(s[IP].dst) +" --> Port Number  " + str(s[TCP].dport)+ " is closed"
       
	for s in unans:
		    print str(s[IP].dst) +" --> Port Number " +str(s[TCP].dport)+ " is open/filtered"
else:
	i=0
	while i<len(portlist):
		port=int(portlist[i])
		if len(sys.argv) ==5:
			if extra == "-verbose":
				response = sr1(IP(dst=ip)/TCP(dport=port,flags='F'),timeout=1,verbose=1)
			if extra == "--packet_trace" :		
				sniff(iface='eth0',filter="ip",prn=sniffPackets,timeout=1)
				response = sr1(IP(dst=ip)/TCP(dport=int(port),flags='F'),timeout=1,verbose=0)
				
		else:
			response = sr1(IP(dst=ip)/TCP(dport=port,flags='F'),timeout=1,verbose=0)

		if response == None:
		
			print port," is open/filtered\n"				
		
		else:
		
			print port," is closed\n"	
		i=i+1	



