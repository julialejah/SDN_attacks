## script to test creation of containers in containernet ##
## and the execution of a function for attack in the network ##
## injection of hosts using method in  https://www.mdpi.com/2076-3417/12/3/1103/htm

#from mininet.net import Containernet
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
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
#from packetin import pingen
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
h3 = net.addDocker( 'h3' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h4 = net.addDocker( 'h4' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h5 = net.addDocker( 'h9' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h6 = net.addDocker( 'h0' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h7 = net.addDocker( 'h7' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h8 = net.addDocker( 'h8' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h9 = net.addDocker( 'h9' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
h0 = net.addDocker( 'h0' , dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
hClient = net.addDocker( 'hClient', dimage="scapy", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
hServer = net.addDocker( 'hServer' , dimage="ubuntu:trusty", volumes=[dirhome+"/SDN_attacks/pyscripts/attacks:/root/:rw"])
#volumes=["/:/mnt/vol1:rw"]
s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')#,controller=RemoteController,ip=contip)
s2 = net.addSwitch( 's2' ,cls=OVSSwitch, protocols="OpenFlow13")#,controller=RemoteController,ip=contip)
s3 = net.addSwitch( 's3' ,cls=OVSSwitch, protocols="OpenFlow13")#,controller=RemoteController,ip=contip)
#bw=100
s4 = net.addSwitch('s4', cls=OVSSwitch, protocols="OpenFlow13")
#bw=100

#hosts = [h1, h2, h3, h4, h5, h6, h7, h8, h9, h0, hClient]
hosts = [h1, h2, h0, hClient]

net.addLink( s1, h1 )#, bw=bw)
net.addLink( s1, h2 )#, bw=bw)
net.addLink( s1, h3 )#, bw=bw)
net.addLink( s1, h4 )#, bw=bw)
net.addLink( s1, h5 )#, bw=bw)
net.addLink( s2, h6 )#, bw=bw)
net.addLink( s2, h7 )#, bw=bw)
net.addLink( s2, h8 )#, bw=bw)
net.addLink( s2, h9 )#, bw=bw)
net.addLink( s2, h0 )#, bw=bw)
net.addLink( s1, s2)
net.addLink( s1, hClient )#, bw=bw)
net.addLink( s2, hServer)#, bw=bw )

net.get('s1').start([c0])
net.get('s2').start([c0])
net.get('s3').start([c0])
net.get('s4').start([c0])

info('*** Starting network\n')
net.build()
for controller in net.controllers:
    controller.start()
    print(controller,' is available: ',c0.isAvailable())
net.get('s1').start([c0])
net.get('s2').start([c0])
print('network started')

info('*** Testing connectivity\n')
time.sleep(10)
net.ping([hClient, hServer])
#net.pingAll()
net.ping([h0,h1,h2])
#info ('*** pingall end\n')
#info('***end pingall***\n')
time.sleep(10)
info('***start randmac***\n')

for i in hosts:
    i.cmd('python3 /root/rdmac.py '+hServer.MAC()+' '+hServer.IP())

#hClient.cmd('python3 /root/packetin.py')
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()
