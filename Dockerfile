#
# Dockerfile for Pcap4J
#

FROM openjdk:11-jdk-slim

# Install libpcap.
RUN apt-get update && \
  apt-get install -y libpcap0.8 git

# Build Pcap4J.
RUN cd /usr/local/src/ && \
  git clone -b v1 git://github.com/kaitoy/pcap4j.git
WORKDIR /usr/local/src/pcap4j
RUN ./mvnw --global-toolchains /usr/local/src/pcap4j/mvn/toolchains_docker_11.xml -P distribution-assembly install 2>&1 | tee build.log

# Collect libraries.
RUN mkdir bin && \
    cd pcap4j-packetfactory-static && \
    ../mvnw -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeScope=compile dependency:copy-dependencies && \
    ../mvnw -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeGroupIds=ch.qos.logback dependency:copy-dependencies && \
    cd ../pcap4j-distribution && \
    ../mvnw -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeArtifactIds=pcap4j-packetfactory-static,pcap4j-sample dependency:copy-dependencies

# Generate sample script. (/usr/local/src/pcap4j/bin/capture.sh)
RUN echo '#!/bin/sh' > bin/capture.sh && \
    echo java -cp /usr/local/src/pcap4j/bin/pcap4j-core.jar:/usr/local/src/pcap4j/bin/pcap4j-packetfactory-static.jar:/usr/local/src/pcap4j/bin/pcap4j-sample.jar:/usr/local/src/pcap4j/bin/jna.jar:/usr/local/src/pcap4j/bin/slf4j-api.jar:/usr/local/src/pcap4j/bin/logback-classic.jar:/usr/local/src/pcap4j/bin/logback-core.jar -Dorg.pcap4j.sample.Docker.nifName=\$1 -Dorg.pcap4j.sample.Docker.wait=\$2 -Dorg.pcap4j.sample.Docker.count=10 org.pcap4j.sample.Docker \$3 >> bin/capture.sh && \
    chmod +x bin/capture.sh

ENTRYPOINT ["/bin/sh", "/usr/local/src/pcap4j/bin/capture.sh"]
CMD ["eth0", "false"]
