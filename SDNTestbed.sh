
#Build images from dockerfile
sudo docker build --tag=scapy -f ../example-containers/scapy/Dockerfile  ../example-containers/scapy
sudo docker build --tag=odl -f ../example-containers/odl/Dockerfile  ../example-containers/odl
