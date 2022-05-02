
#Build images from dockerfile
sudo docker build --tag=scapy -f containernet/Dockerfile/scapy/Dockerfile  containernet/Dockerfile/scapy
sudo docker build --tag=odl_f -f containernet/Dockerfile/odl/Dockerfile  containernet/Dockerfile/odl

#Create directory for the dockers in file "red2.py"
sudo mkdir /home/juli/shvol

#run the odl docker
sudo docker run -d -p 6633:6633 -p 8101:8101 -p 8181:8181 --name=odl odl_f
