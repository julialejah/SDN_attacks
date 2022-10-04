#! /usr/bin/env python
#creates a fake link between 2 hosts
## Args [1] = name of the second host

from scapy.contrib.lldp import *
import sys
import threading
from scapy.all import *
import time
import socket
import pyshark
import os
import json
from scapy.all import sniff
import requests
from fastapi import FastAPI

# function to send LLDP packets and simulate a link
_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))
def _layer2dict(obj):
    d = {}
    if not getattr(obj, 'fields_desc', None):
        return
    for f in obj.fields_desc:
        value = getattr(obj, f.name)
        if value is type(None):
            value = None
        if not isinstance(value, _native_value):
            value = _layer2dict(value)
        if type(value) is bytes:
            d[f.name] = str(value)
        else:
            d[f.name] = value
    return {obj.name: d}

# Adapted from https://github.com/littlezz/scapy2dict
def to_dict(p):
    """
    Turn every layer to dict, store in list.
    :return: list
    """
    d = list()
    count = 0
    while True:
        layer = p.getlayer(count)
        if not layer:
            break
        d.append(_layer2dict(layer))
        count += 1
    return d


def get_ifa():
    ifs=os.listdir('/sys/class/net/')
    for i in range(len(ifs)):
        if ifs[i] != 'lo' and ifs[i]!= 'eth0':
            ifa = ifs[i]
    print ('ifa es: '+ifa)
    return ifa

def linkfabr(ifa,hostname):
    print('entra 1')
    lim = 0
    lpc = 0
    lis =[]
    lld =[]  
    while lim<10  :
        pkt = sniff(count=1,iface=ifa)[0]
        data = to_dict(pkt)
        ethtype=data[0]['Ethernet']['type']
        if ethtype == 0x88cc:
            lim = lim + 1
            print('lldp')
            with open("/root/lldppack_"+hostname+"_"+str(lim)+".pk",'w',encoding = 'utf-8') as f:
                f.write(str(pkt))


def getlldppack(host_2,ifa):
    lim = 0
    log = "/root/log.log"
    file = "/root/lldppack_"+str(host_2)+"_"+str(lim)+".pk"
    while lim<10:
        try:
            with open (file) as f:
                pack = f.read()
        except:
            with open(log,'a') as lf:
                lf.write("error when reading the packet "+file+"\n")
            time.sleep(8)
        else:
            print("lee")
            sendp(pack,count=1, iface=ifa)
            print(pack)
            lim = lim +1
            with open(log,'a') as lf:
                lf.write('read packet '+file+"\n")

ifa = get_ifa()
host_2=sys.argv[1]
print(host_2)
getpack = threading.Thread(target=getlldppack,args=[host_2,ifa])
getpack.start()
hostname = socket.gethostname()
print(ifa)#ifa = 'enp2s0'
linkfabr(ifa,hostname)
