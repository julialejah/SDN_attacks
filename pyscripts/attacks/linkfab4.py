
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
#import requests
#from fastapi import FastAPI
import pandas as pd
pd.set_option('display.max_columns', 100)

# function to send LLDP packets and simulate a link
_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))
def _layer2df(obj):
    df = pd.DataFrame(columns=["Layer","Field","Value"])
    if not getattr(obj, 'fields_desc', None):
        return
    for f in obj.fields_desc:
        value = getattr(obj, f.name)
        if value is type(None):
            value = None
        if not isinstance(value, _native_value):
            value = _layer2df(value)
        #if type(value) is bytes:
           # d[f.name] = str(value)
#            print('type: '+type(str(value).encode()))
        else:
             df=df.append({"Layer":str(obj.name),"Field":str(f.name),"Value":str(value)},ignore_index=True)
    return (df)

# Adapted from https://github.com/littlezz/scapy2dict
def to_dataframe(p):
    """
    Turn every layer rows in df
    """
    df = pd.DataFrame(columns=["Layer","Field","Value"])
    count = 0
    while True:
        layer = p.getlayer(count)
        if not layer:
            break
        cap=_layer2df(layer)
        df = df.append(cap)
        count += 1
#    print(df)
    return (df)


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
        data = to_dataframe(pkt)
        ethtype = int(data.loc[(data['Layer']=='Ethernet')&(data['Field']=='type')].iloc[0,2])
        print(ethtype)
        if ethtype == 0x88cc:
            lim = lim + 1
            print('lldp')
#            with open("/root/lldppack_"+hostname+"_"+str(lim)+".pk",'w',encoding = 'utf-8') as f:
#                f.write(str(pkt))
            with open ("/root/dic_"+hostname+"_"+str(lim)+".dic",'w') as f:
                f.write(str(data))            


def getlldppack(host_2,ifa):
    print("entra func thre")
    lim = 1
    log = "/root/log.log"
    file = "/root/dic_"+str(host_2)+"_"+str(lim)+".dic"
    while lim<10:
        try:
            with open (file) as f:
                lldp1 = f.read()
        except:
            with open(log,'a') as lf:
                lf.write("error when reading the packet "+file+"\n")
            time.sleep(8)
        else:
            lldp1 = lldp1.replace(" None,","")
            lldp1 = lldp1.replace("[","")
            lldp1 = lldp1.replace("]","")
            lldp1 = lldp1.replace(": ","= ")
            lldp1 = lldp1.replace("'_"," _")
            lldp1 = lldp1.replace(" '","  ")
            lldp1 = lldp1.replace("'}"," }")
            lldp1 = lldp1.replace("'="," =")

            ind2 = lldp1.index("LLDPDUChassisID")
            chassisid = lldp1[ind2+19:ind2+94]
            ind1 = lldp1.index("LLDPDUPortID")
            portid = lldp1[ind1+16:ind1+77]
            ind3 = lldp1.index("LLDPDUTimeToLive")
            ttl = lldp1[ind3+20:ind3+57]
            ind4 = lldp1.index("LLDPDUSystemName")
            sysname = lldp1[ind4+20:ind4+76]
            ind5 = lldp1.index("LLDPDUGenericOrganisationSpecific")
            genorgspec1 = lldp1[ind5+37:ind5+122]
            ind6=ind5+130
            genorgspec2 = lldp1[ind6+37:ind6+162]
            ind7 = lldp1.index("LLDPDUEndOfLLDPDU")
            end = lldp1[ind7+21:ind7+45]
            print(portid) 
            print(chassisid) 
            print(ttl) 
            print(sysname) 
            print(genorgspec1)
            print(genorgspec2) 
            print(end) 
            e = Ether()
            lldp = LLDPDUChassisID(_type= 1, _length= 7, subtype= 4, family= None, id= '00:00:00:00:00:01')
          
            sendp(lldppack,count=1, iface=ifa)
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
