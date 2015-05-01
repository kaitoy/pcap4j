#
# Dockerfile for Pcap4J on CentOS
#

FROM centos:6
MAINTAINER Kaito Yamada <kaitoy@pcap4j.org>

## Install packages.
RUN yum install -y libpcap
RUN yum install -y git
#RUN yum install -y java-1.7.0-openjdk
#RUN yum install -y java-1.7.0-openjdk-devel
RUN curl  https://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo -o /etc/yum.repos.d/epel-apache-maven.repo -k
RUN yum install -y apache-maven

## Build Pcap4J.
#RUN export JAVA_HOME=/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.79.x86_64
RUN export JAVA_HOME=/usr/lib/jvm/java-1.6.0-openjdk-1.6.0.35.x86_64/
RUN cd /usr/local/src/ && git clone https://github.com/kaitoy/pcap4j.git
RUN cd pcap4j && mvn install > build.log 2>&1

## Generate sample script.
RUN mkdir bin
RUN cd pcap4j-packetfactory-static
RUN mvn -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeScope=compile dependency:copy-dependencies
RUN mvn -DoutputDirectory=/usr/local/src/pcap4j/bin -Dmdep.stripVersion=true -DincludeGroupIds=ch.qos.logback dependency:copy-dependencies
RUN cd ../bin
RUN cp ../pcap4j-sample/target/*.jar ./pcap4j-sample.jar
RUN cp ../pcap4j-packetfactory-static/target/*.jar ./pcap4j-packetfactory-static.jar
RUN echo '#!/bin/sh' > runLoop.sh
RUN echo java -cp pcap4j-core.jar:pcap4j-packetfactory-static.jar:pcap4j-sample.jar:jna.jar:slf4j-api.jar:logback-classic.jar:logback-core.jar org.pcap4j.sample.Loop >> runLoop.sh
RUN chmod +x runLoop.sh
