# packet sniff

from scapy.all import *

packet = sniff(iface="eth0", filter ="tcp and( port 80)", timeout=10, count=5)


print packet.summary()
