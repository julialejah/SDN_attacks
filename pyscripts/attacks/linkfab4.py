#! /usr/bin/env python
#creates a fake link between 2 hosts
## Args [1] = name of the second host

from binascii import hexlify
from termios import B50
from scapy.contrib.lldp import *
import sys
import threading
from scapy.all import *
import time
import socket
import pyshark
import os
import json
import base64
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
        if type(value) is bytes:
            print(len(value))
            print(value)
            try:
                aux=int(value)
                print("decode int")
                df=df.append({"Layer":str(obj.name),"Field":str(f.name),"Value":aux},ignore_index=True)
            except:
                try:
                    hval=value.decode("utf-8")
                    print("decode utf-8")
                    df=df.append({"Layer":str(obj.name),"Field":str(f.name),"Value":hval},ignore_index=True)
                except:
                    hval=base64.b64encode(value)
                    print(hval)
                    print("decode base64")
                    df=df.append({"Layer":str(obj.name),"Field":str(f.name),"Value":hval},ignore_index=True)
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
    return (df)


def get_ifa():
    ifs=os.listdir('/sys/class/net/')
    for i in range(len(ifs)):
        if ifs[i] != 'lo' and ifs[i]!= 'eth0':
            ifa = ifs[i]
    print ('ifa es: '+ifa)
    return ifa

def linkfabr(ifa,hostname):
    lim = 0
    lpc = 0
    lis =[]
    lld =[]  
    while lim<10 and flag :
        pkt = sniff(count=1,iface=ifa)[0]
        data = to_dataframe(pkt)
        # print(data)
        print(data.loc[(data['Layer']=='Ethernet')&(data['Field']=='type')])#.iloc[0,2])
        ethtype = int(data.loc[(data['Layer']=='Ethernet')&(data['Field']=='type')].iloc[0,2])
        if ethtype == 0x88cc:
            lim = lim + 1
            print('lldp')
            data.to_csv ("/root/dic_"+hostname+"_"+str(lim)+".csv")


def getlldppack(host_2,ifa):
    lim = 1
    log = "/root/log.log"
    file = "/root/dic_"+str(host_2)+"_"+str(lim)+".csv"
    while lim<10:
        try:
            lldp1 = pd.read_csv(file)
        except:
            with open(log,'a') as lf:
                lf.write("error when reading the packet "+file+" for count "+str(lim)+"\n")
            time.sleep(8)
        else:
            lldp1 = lldp1.iloc[: , 1:]

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
            b5=int(lldp1.loc[(lldp1['Layer']=='LLDPDUPortID')&(lldp1['Field']=='id')].iloc[0,2])
            c1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='_type')].iloc[0,2])
            c2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='_length')].iloc[0,2])
            c3=int(lldp1.loc[(lldp1['Layer']=='LLDPDUTimeToLive')&(lldp1['Field']=='ttl')].iloc[0,2])
            d1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='_type')].iloc[0,2])
            d2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='_length')].iloc[0,2])
            d3=lldp1.loc[(lldp1['Layer']=='LLDPDUSystemName')&(lldp1['Field']=='system_name')].iloc[0,2]
            e1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_type')].iloc[0,2])
            e2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_length')].iloc[0,2])
            e3=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='org_code')].iloc[0,2])
            e4=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='subtype')].iloc[0,2])
            e5=lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='data')].iloc[0,2]
            f1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_type')].iloc[1,2])
            f2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='_length')].iloc[1,2])
            f3=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='org_code')].iloc[1,2])
            f4=int(lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='subtype')].iloc[1,2])
            f5=lldp1.loc[(lldp1['Layer']=='LLDPDUGenericOrganisationSpecific')&(lldp1['Field']=='data')].iloc[1,2]
            g1=int(lldp1.loc[(lldp1['Layer']=='LLDPDUEndOfLLDPDU')&(lldp1['Field']=='_type')].iloc[0,2])
            g2=int(lldp1.loc[(lldp1['Layer']=='LLDPDUEndOfLLDPDU')&(lldp1['Field']=='_length')].iloc[0,2])
           
            print("b1 from dataframe converted to int is ---> "+str(b1))
            print("b2 from dataframe converted to int is ---> "+str(b2))
            print("b3 from dataframe converted to int is ---> "+str(b3))
            print("b4 from dataframe converted to int is ---> "+str(b4))
            print("b5 from dataframe converted to int is ---> "+str(b5))
                        
            l1 = LLDPDUChassisID(_type=a1,_length=a2,subtype=a3,family=a4,id=a5)
            l2 = LLDPDUPortID(_type=2,_length=2,subtype=7,family=None,id=1)
            l3 = LLDPDUTimeToLive(_type=c1,_length=c2,ttl=c3)
            l4 = LLDPDUSystemName(_type=d1,_length=d2,system_name=d3)
            l5 = LLDPDUGenericOrganisationSpecific(_type=e1,_length=e2,org_code=e3,subtype=e4,data=e5)

            print("f5 from dataframe is ---->>> "+str(f5))
            print("clean f5 from dataframe is ---->>> "+str(f5[2:-1]))
            dato = base64.b64decode(f5[2:-1])
            print(dato)
            print(type(dato))
            print("to str: "+str(dato))
            print("-----------------------------------------")
            print("to bytes: "+str(bytes(dato)))

            l6 = LLDPDUGenericOrganisationSpecific(_type=f1,_length=f2,org_code=f3,subtype=f4,data=dato)
            l7 = LLDPDUEndOfLLDPDU(_type=0,_length=0)
            lldpu_layer = LLDPDU()
            lldpu_layer = l1/l2/l3/l4/l5/l6/l7
#            lldpu_layer = l1/l2/l3/l4/l6/l7
            
            pack = e/lldpu_layer
            print(pack.show2())

            flag = False
            sendp(pack,count=1, iface=ifa)
            flag = True
            lim = lim +1

            with open(log,'a') as lf:
                lf.write('read packet '+file+"\n")
    l6f = l5 = LLDPDUGenericOrganisationSpecific(_type=e1,_length=e2,org_code=e3,subtype=e4,data="script_ending123")
    packf = e/l1/l2/l3/l4/l6f/l7
    sendp(packf,count=1, iface=ifa)

ifa = get_ifa()        
host_2=sys.argv[1]
print(host_2)
getpack = threading.Thread(target=getlldppack,args=[host_2,ifa])
getpack.start()
hostname = socket.gethostname()
print(ifa)#ifa = 'enp2s0'
linkfabr(ifa,hostname)
print(flag)