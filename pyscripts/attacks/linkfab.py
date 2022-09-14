#! /usr/bin/env python

import sys
import threading
import time
import socket
import pyshark
import os
# function to send LLDP packets and simulate a link

def get_ifa():
    ifs=os.listdir('/sys/class/net/')
    for i in range(len(ifs)):
        if ifs[i] != 'lo' and ifs[i]!= 'eth0':
            ifa = ifs[i]
#    print ('ifa es: '+ifa)
    return ifa

def linkfabr(ifa):
    print('entra 1')
    lim = 0
    lis =[]
    lld =[]  
    name=socket.gethostname()
    lbool=False
    while lim<10000  :
        cap = pyshark.LiveRingCapture(interface=ifa)
        cap.sniff(packet_count=1)
        p = cap[0]
        frame_type=getattr(p.eth,'type')
        print(type(frame_type))
        if frame_type == '0x000088cc':
            with open('/root/'+str(name)+'llpack','a') as f: #option a for append
#                print(dir(p))
                info=p.lldp
                f.write(str(info)+'\n\n')
#            print('llega lldp')
            lld.append(p)
        lim = lim + 1
        lld.append(p)
        with open('/root/'+str(name)+'_capture.txt','a') as f:
            f.write('Frame type: '+str(frame_type)+'\n')
            f.write('format: '+str(type(frame_type))+'\n')
            f.write(str(p.show)+'\n\n')
        print('*')

ifa = get_ifa()
linkfabr(ifa)
