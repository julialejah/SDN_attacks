#! /usr/bin/env python
#creates a fake link between 2 hosts
#takes the first argument to define the host

from scapy.contrib.lldp import *
import sys
import threading
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
#            print('type: '+type(str(value).encode()))
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
    print('Paquete: \n'+str(p))
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

def linkfabr(ifa):
    print('entra 1')
    lim = 0
    lpc = 0
    lis =[]
    lld =[]  
    while lim<1000  :
        lim = lim + 1
        pkt = sniff(count=1,iface=ifa)[0]
        data = to_dict(pkt)
        ethtype=data[0]['Ethernet']['type']
        if ethtype == 0x88cc:
            print('lldp')
            with open("/root/lldppack_"+name+".json",'w',encoding = 'utf-8') as f:
                f.write(pkt)
            json_object = json.dumps(data)
            print(json_object)
        break

def getlldppack():
    while true:
        host_2=sys.argv[1]
        file = "/root/lldppack_"+str(host_2)
        with open (file,r) as f:
            pack = f.read(json_pack)
        json_object = jason.loads(pack)
#for i in range(len(data)):
#                json_object = json.dumps(data[i])
#        y=json.dumps(d)
#        print(y) 


#app = FastAPI()
#@app.get("/getmsg")
#def getmsg ():
#    return {
#        "message": "Hello World"
#} 

name=socket.gethostname()
ifa = get_ifa()
print(ifa)#ifa = 'enp2s0'
linkfabr(ifa)
