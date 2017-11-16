# send packet again and again

from scapy.all import *

packet =IP(dst="10.100.52.219")/ICMP()/"hello packet"

send(packet, loop=1)

packet.show()
