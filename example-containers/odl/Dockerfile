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
    apt-get install -y net-tools \
    apt-get clean;
    
# Setup JAVA_HOME -- useful for docker commandline
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/jre
RUN export JAVA_HOME

# Download ODL 
RUN curl -XGET -O https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/karaf/0.8.1/karaf-0.8.1.tar.gz
RUN tar -C /opt/ -xvzf karaf-0.8.1.tar.gz
#RUN echo 'featuresBoot = odl-openflowplugin-libraries odl-mdsal-all odl-l2switch-all odl-restconf-all odl-yangtools-common odl-dlux-core' >> /karaf-0.8.1/etc/org.apache.karaf.features.cfg
