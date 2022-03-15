#Dockerfile for a container of a Client host, that could
#act as an attacker to the net (with scapy)

# parent image
FROM ubuntu:bionic
# environment variables
ENV TZ=America/Bogota
#ENV DEBIAN_FRONTEND=noninteractive  
# install needed packages
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone &&\
    DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    iproute2 \
    telnet telnetd \
    hping3 \
    iperf \
    python3-pip \
    tcpdump \
    && pip3 install scapy

# run bash interpreter
CMD /bin/bash
