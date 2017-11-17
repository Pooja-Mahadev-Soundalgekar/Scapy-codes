#!/usr/bin/python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

response = sr1(IP(dst="216.58.196.101")/TCP(dport=80,flags='S'))
response.display()
reply = sr1(IP(dst="216.58.196.101")/TCP(dport=80,flags='A',ack=(response[TCP].seq + 1)))
reply.display()
