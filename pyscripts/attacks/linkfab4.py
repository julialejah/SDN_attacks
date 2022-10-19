


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

flag = True;

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
    while lim<10 and flag :
        pkt = sniff(count=1,iface=ifa)[0]
        data = to_dataframe(pkt)
        ethtype = int(data.loc[(data['Layer']=='Ethernet')&(data['Field']=='type')].iloc[0,2])
        print(ethtype)
        if ethtype == 0x88cc:
            lim = lim + 1
            print('lldp')
            data.to_csv ("/root/dic_"+hostname+"_"+str(lim)+".csv")


def getlldppack(host_2,ifa):
    print("entra func thre")
    lim = 1
    log = "/root/log.log"
    file = "/root/dic_"+str(host_2)+"_"+str(lim)+".csv"
    while lim<10:
        print(lim)
        try:
            lldp1 = pd.read_csv(file)
        except:
            with open(log,'a') as lf:
                lf.write("error when reading the packet "+file+"\n")
            time.sleep(8)
        else:
            lldp1 = lldp1.iloc[: , 1:]
            print(lldp1) 

            e1=lldp1.loc[(lldp1['Layer']=='Ethernet')&(lldp1['Field']=='dst')].iloc[0,2]
            e2=lldp1.loc[(lldp1['Layer']=='Ethernet')&(lldp1['Field']=='src')].iloc[0,2]
            e3=int(lldp1.loc[(lldp1['Layer']=='Ethernet')&(lldp1['Field']=='type')].iloc[0,2])
            e = Ether(dst=e1, src=e2, type=e3)
            a1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUChassisID')&(lldp1['Field']=='_type')].iloc[0,2])
            a2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUChassisID')&(lldp1['Field']=='_length')].iloc[0,2])
            a3=int(lldp1.loc[(lldp1['Layer']=='LLDPDUChassisID')&(lldp1['Field']=='subtype')].iloc[0,2])
            a4=lldp1.loc[(lldp1['Layer']=='LLDPDUChassisID')&(lldp1['Field']=='family')].iloc[0,2]
            a5=lldp1.loc[(lldp1['Layer']=='LLDPDUChassisID')&(lldp1['Field']=='id')].iloc[0,2]
            b1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='_type')].iloc[0,2])
            b2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='_length')].iloc[0,2])
            b3=int(lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='subtype')].iloc[0,2])
            b4=lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='family')].iloc[0,2]
            b5=lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='id')].iloc[0,2]
            c1=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='_type')].iloc[0,2],encoding='utf8')
            c2=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='_length')].iloc[0,2],encoding='utf8')
            c3=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='ttl')].iloc[0,2],encoding='utf8')
            d1=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='_type')].iloc[0,2],encoding='utf8')
            d2=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='_length')].iloc[0,2],encoding='utf8')
            d3=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='system_name')].iloc[0,2],encoding='utf8')
            e1=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_type')].iloc[0,2],encoding='utf8')
            e2=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_length')].iloc[0,2],encoding='utf8')
            e3=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='org_code')].iloc[0,2],encoding='utf8')
            e4=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='subtype')].iloc[0,2],encoding='utf8')
            e5=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='data')].iloc[0,2],encoding='utf8')
            f1=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_type')].iloc[1,2],encoding='utf8')
            f2=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_length')].iloc[1,2],encoding='utf8')
            f3=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='org_code')].iloc[1,2],encoding='utf8')
            f4=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='subtype')].iloc[1,2],encoding='utf8')
            f5=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='data')].iloc[1,2],encoding='utf8')
            g1=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUEndOfLLDPDU')&(lldp1['Field']=='_type')].iloc[0,2],encoding='utf8')
            g2=bytearray(lldp1.loc[(lldp1['Layer']=='LLDPDUEndOfLLDPDU')&(lldp1['Field']=='_length')].iloc[0,2],encoding='utf8')
            print("a5 = "+str(a5)+" is type: ")
            print(type(a5))
            print("a3 = "+str(a3)+" is type: ")
            print(type(a3))
            print("a4 = "+str(a4)+" is type: ")
            print(type(a4))


            l1 = LLDPDUChassisID(_type=a1,_length=a2,subtype=a3,family=a4,id=a5)
            l2 = LLDPDUPortID(_type=b1,_length=b2,subtype=b3,family=b4,id=b5)
            l3 = LLDPDUTimeToLive(_type=c1,_length=c2,ttl=c3)
            l4 = LLDPDUSystemName(_type=d1,_length=d2,system_name=d3)
            l5 = LLDPDUGenericOrganisationSpecific(_type=e1,_length=e2,org_code=e3,subtype=e4,data=e5)
            l6 = LLDPDUGenericOrganisationSpecific(_type=f1,_length=f2,org_code=f3,subtype=f4,data=f5)
            l7 = LLDPDUEndOfLLDPDU(_type=g1,_length=g2)
#            pack = e/l1/l2/l3/l4/l5/l6/l7
            pack = e/l1/l2
            flag = False
            sendp(pack,count=1, iface=ifa)
            flag = True
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
