# parent image
FROM ubuntu:20.04
# environment variables
ENV TZ=America/Bogota
ENV DEBIAN_FRONTEND=noninteractive  
# install needed packages

# Install OpenJDK-8
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone 
RUN apt-get update && \
    apt-get install -y openjdk-8-jdk && \
    apt-get install -y ant curl unzip && \
    apt-get install -y net-tools && \
    apt-get clean;
    
# Setup JAVA_HOME -- useful for docker commandline
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/jre
RUN export JAVA_HOME

# Download ODL 
RUN curl -XGET -O https://nexus.opendaylight.org/content/repositories/opendaylight.release/o$
RUN tar -xvzf karaf-0.8.4.tar.gz

# Install the required features
RUN sed -i 's/0af5d86a-980c-48a9-a02d-bdac71ff8529/odl-openflowplugin-libraries odl-mdsal-al$

# run karaf
RUN karaf-0.8.4/bin/karaf
