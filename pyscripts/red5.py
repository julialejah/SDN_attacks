## script to test creation of containers in containernet ##
## and the execution of a function for attack in the network ##
## Link fabrication attack and injection of hosts 
## using method in  https://www.mdpi.com/2076-3417/12/3/1103/htm host injection
## using method in Soltani, S., Shojafar, M., Mostafaei, H., Pooranian, Z., & Tafazolli, R. (2021). Link Latency Attack in Software-Defined Networks. Proceedings of the 2021 17th International Conference on Network and Service Management: Smart Management for Future Networks and Services, CNSM 2021, 187–193. https://doi.org/10.23919/CNSM52442.2021.9615598
## ip of the controller is the first parameter
import requests
import json
import xml.etree.ElementTree as ET
import sys
from mininet.net import Containernet
from mininet.node import Controller
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.link import OVSLink
from mininet.log import info, setLogLevel
import scapy.all as scapy
import time

contip = sys.argv[1]
dirhome = sys.argv[2]

setLogLevel('info')
net = Containernet(link=TCLink)
c0 = RemoteController (name='C0',controller=RemoteController, 
			port=6653,  ip= contip)
info('*** controller ok \n')
h1 = net.addDocker( 'h1' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h2 = net.addDocker( 'h2' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h9 = net.addDocker( 'h9' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h0 = net.addDocker( 'h0' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
hClient = net.addDocker( 'hClient', dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
hServer = net.addDocker( 'hServer' , dimage="ubuntu:trusty", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
#volumes=["/:/mnt/vol1:rw"]
s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')#,controller=RemoteController,ip=contip)
s2 = net.addSwitch( 's2' ,cls=OVSSwitch, protocols="OpenFlow13")#,controller=RemoteController,ip=contip)
s3 = net.addSwitch( 's3' ,cls=OVSSwitch, protocols="OpenFlow13")#,controller=RemoteController,ip=contip)
#bw=100

#hosts = [h1, h2, h3, h4, h5, h6, h7, h8, h9, h0, hClient]
hosts = [h1, h2, h0, h9, hClient]

net.addLink( s1, h1 )#, bw=bw)
net.addLink( s1, h2 )#, bw=bw)
net.addLink( s2, h0 )#, bw=bw)
net.addLink( s1, s2)
net.addLink( s2, s3)
net.addLink( s1, s3)
net.addLink( s1, hClient )#, bw=bw)
net.addLink( s2, hServer)#, bw=bw )
net.addLink( s2, h9)

info('*** Starting network\n')
net.build()
for controller in net.controllers:
    controller.start()
    print(controller,' is available: ',c0.isAvailable())
net.get('s1').start([c0])
net.get('s2').start([c0])
print('network started')

info('*** Testing connectivity\n')
for i in hosts:
    #i.cmd('touch /root/net1.pcap')
    i.cmd('nohup python3 /root/linkfab.py &')
time.sleep(5)
net.ping([hClient, hServer])
net.ping([h0,h1,h2])
time.sleep(10)

info('***start randmac with DoS attack***\n')
#print (hServer.MAC())
#print (hServer.IP())

for i in hosts:
    i.cmd('nohup python3 /root/rdmac3.py '+hServer.MAC()+' '+hServer.IP()+' '+str(2)+' &')
    print('ataque en '+str(i)+'\n')
print('*****')
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()
