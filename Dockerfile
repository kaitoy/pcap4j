#
# Dockerfile for Pcap4J on CentOS
#

FROM centos:6
MAINTAINER Kaito Yamada <kaitoy@pcap4j.org>

# Install packages.
ADD https://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo /etc/yum.repos.d/epel-apache-maven.repo
RUN yum install -y libpcap \
    git \
    java-1.6.0-openjdk \
    java-1.6.0-openjdk-devel \
    apache-maven

# Build Pcap4J.
ENV JAVA_HOME /usr/lib/jvm/java-1.6.0-openjdk.x86_64/
RUN cd /usr/local/src/ && git clone git://github.com/kaitoy/pcap4j.git
RUN cd /usr/local/src/pcap4j && mvn install 2>&1 | tee build.log

# Generate sample script.
WORKDIR /usr/local/src/pcap4j
RUN mkdir bin && \
    cd pcap4j-packetfactory-static && \
    mvn -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeScope=compile dependency:copy-dependencies && \
    mvn -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeGroupIds=ch.qos.logback dependency:copy-dependencies && \
    cd ../pcap4j-distribution && \
    mvn -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeArtifactIds=pcap4j-packetfactory-static,pcap4j-sample dependency:copy-dependencies
RUN echo '#!/bin/sh' > bin/runGetNextPacket.sh && \
    echo java -cp /usr/local/src/pcap4j/bin/pcap4j-core.jar:/usr/local/src/pcap4j/bin/pcap4j-packetfactory-static.jar:/usr/local/src/pcap4j/bin/pcap4j-sample.jar:/usr/local/src/pcap4j/bin/jna.jar:/usr/local/src/pcap4j/bin/slf4j-api.jar:/usr/local/src/pcap4j/bin/logback-classic.jar:/usr/local/src/pcap4j/bin/logback-core.jar -Dorg.pcap4j.sample.GetNextPacket.nifName=eth0 org.pcap4j.sample.GetNextPacket >> bin/runGetNextPacket.sh && \
    chmod +x bin/runGetNextPacket.sh

CMD ["/bin/sh", "/usr/local/src/pcap4j/bin/runGetNextPacket.sh"]
