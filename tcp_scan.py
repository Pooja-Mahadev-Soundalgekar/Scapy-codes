#!/usr/bin/python
import logging


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys
if len(sys.argv) != 4:
	print "Usage - ./udp_scan.py [Target-IP] [First Port] [Last Port]"
	print "Example - ./udp_scan.py 10.0.0.5 1 100"
	print "Example will UDP port scan ports 1 through 100 on 10.0.0.5"
        sys.exit()



ip = sys.argv[1]
print ip
start = int(sys.argv[2])
end = int(sys.argv[3])

for port in range(start,end):
	ans = sr1(IP(dst=ip)/TCP(dport=port),timeout=5,verbose=1)
	time.sleep(1)
	if ans == None:
		print port
                #ans.display()
	else:
		ans.display()
		pass
