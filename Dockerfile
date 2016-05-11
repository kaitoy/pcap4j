#
# Dockerfile for Pcap4J
#

FROM java:8
MAINTAINER Kaito Yamada <kaitoy@pcap4j.org>

# Install libpcap.
RUN apt-get update && \
    apt-get install -y libpcap0.8

# Build Pcap4J.
RUN cd /usr/local/src/ && \
    git clone -b master git://github.com/kaitoy/pcap4j.git
WORKDIR /usr/local/src/pcap4j
RUN ./gradlew build --info 2>&1 | tee build.log

# Generate sample script. (/usr/local/src/pcap4j/build/docker_script/capture.sh)
RUN ./gradlew genScriptForDocker
RUN chmod +x build/docker_script/capture.sh

ENTRYPOINT ["/bin/sh", "/usr/local/src/pcap4j/build/docker_script/capture.sh"]
CMD ["eth0", "false"]
