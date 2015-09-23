[Japanese](/README_ja.md)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/pcap4jlogo.png" height="217" width="667" />

[![Slack](http://pcap4j-slackin.herokuapp.com/badge.svg)](https://pcap4j-slackin.herokuapp.com/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution)

[![Build Status](https://travis-ci.org/kaitoy/pcap4j.svg)](https://travis-ci.org/kaitoy/pcap4j)
[![Build status](https://ci.appveyor.com/api/projects/status/github/kaitoy/pcap4j?branch=master&svg=true)](https://ci.appveyor.com/project/kaitoy/pcap4j/branch/master)
[![Coverage Status](https://coveralls.io/repos/kaitoy/pcap4j/badge.svg)](https://coveralls.io/r/kaitoy/pcap4j)

Pcap4J
======

Pcap4J is a Java library for capturing, crafting and sending packets.
Pcap4J wraps a native packet capture library ([libpcap](http://www.tcpdump.org/) or
[WinPcap](http://www.winpcap.org/)) via [JNA](https://github.com/twall/jna)
and provides you Java-Oriented APIs.

Contents
--------

* [Download](#download)
* [Why Pcap4J was born](#why-pcap4j-was-born)
* [Features](#features)
* [How to use](#how-to-use)
    * [System requirements](#system-requirements)
        * [Dependencies](#dependencies)
        * [Platforms](#platforms)
        * [Others](#others)
    * [Documents](#documents)
    * [How to run samples](#how-to-run-samples)
    * [How to use in Maven project](#how-to-use-in-maven-project)
    * [About pcap library loading](#about-pcap-library-loading)
    * [Docker](#docker)
* [How to build](#how-to-build)
    * [Build procedure with Maven command (recommended)](#build-procedure-with-maven-command-recommended)
    * [Build procedure on Eclipse](#build-procedure-on-eclipse)
* [License](#license)
* [Contacts](#contacts)
* [Extra](#extra)

Download
--------

Pcap4J is available on the Maven Central Repository.

* Pcap4J 1.6.1 (latest version on Maven Central Repository)
    * without source: [pcap4j-distribution-1.6.1-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.6.1/pcap4j-distribution-1.6.1-bin.zip)
    * with    source: [pcap4j-distribution-1.6.1-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.6.1/pcap4j-distribution-1.6.1-src.zip)
* Snapshot builds
    * https://oss.sonatype.org/content/repositories/snapshots/org/pcap4j/pcap4j-distribution/

Why Pcap4J was born
-------------------
I have been developing an SNMP network simulator (SNeO, available at the link below) by Java,
which needed to capture packets and I found the [pcap](http://en.wikipedia.org/wiki/Pcap) was useful for it.
Although there are some implementations of the pcap such as libpcap (for UNIX) and WinPcap (for Windows),
because they are both native libraries, a Java wrapper library was necessary in order to use them for SNeO.
I researched it and found three Java wrapper libraries for pcap: [jpcap](http://jpcap.sourceforge.net/),
[jNetPcap](http://jnetpcap.com/), and [Jpcap](http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/).
But both jpcap and jNetPcap were unsuitable for SNeO because they seemed to be designed for mainly capturing packets
and not to be useful for making and sending packets so much. On the other hand, Jpcap looked useful for
making and sending packets. But it had a defect in capturing ICMP packets and
its development seemed to be stopped long ago.
That's why I started developing Pcap4j.

Features
--------

* Capturing packets via a network interface and converting them into Java objects.
  You can get/set each field of a packet header via the Java object converted from the packet.
  You can also craft a packet object from scratch.
* Sending packet objects to a real network.
* Supported protocols:
    * Ethernet, Linux SLL, raw IP, PPP (RFC1661, RFC1662), and BSD (Mac OS X) loopback encapsulation
    * IEEE802.1Q
    * ARP
    * IPv4 (RFC791 and RFC1349) and IPv6 (RFC2460)
    * ICMPv4 (RFC792) and ICMPv6 (RFC4443, RFC4861)
    * TCP (RFC793, RFC2018, and draft-ietf-tcpm-1323bis-21) and UDP
* All built-in packet classes are serializable and thread-safe (practically immutable).
* You can add a protocol support without modifying Pcap4J library itself.
* Dumping and reading pcap-formatted files (e.g. a capture file of Wireshark).

How to use
----------

#### System requirements ####

##### Dependencies #####
Pcap4j 1.1.0 or older needs J2SE 5.0+. Pcap4j 1.2.0 or newer needs J2SE 6.0+.
And also libpcap 1.0.0+ or WinPcap 3.0+, jna, slf4j-api, and an implementation of logger for slf4j are required.
I'm using the following libraries for the test.

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 4.1.0
* slf4j-api 1.7.12
* logback-core 1.0.0
* logback-classic 1.0.0

##### Platforms #####
I tested Pcap4j on the following OSes with x86 processors.

* Windows: XP, Vista, 7, 2003 R2, 2008, 2008 R2, and 2012
* Linux
    * RHEL: 5 and 6
    * CentOS: 5
    * Ubuntu: 13
* UNIX
    * Solaris: 10
    * FreeBSD: 10

And tomute tested Pcap4j on Mac OS X. The report is [here](http://tomute.hateblo.jp/entry/2013/01/27/003209). Thank you, tomute!

I hope Pcap4j can run on the other OSes supported by both JNA and libpcap.

##### Others #####
Pcap4J needs administrator/root privileges.
Or, if on Linux, you can run Pcap4J with a non-root user by granting capabilities `CAP_NET_RAW` and `CAP_NET_ADMIN`
to your java command by the following command: `setcap cap_net_raw,cap_net_admin=eip /path/to/java`

#### Documents ####
The latest JavaDoc is [here](http://kaitoy.github.com/pcap4j/javadoc/latest/en).
Each version's JavaDoc is on the [Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22).

Refer to [here](/www/pcap4j_modules.md) for information about Pcap4J modules.

Because Pcap4J is a wrapper library of libpcap/WinPcap, the following documents help you to understand how to use Pcap4J.

* [Programming with pcap](http://www.tcpdump.org/pcap.html)
* [WinPcap Manuals](http://www.winpcap.org/docs/default.htm)
* [Mapping between pcap API and Pcap4J API](/www/api_mappings.md)

You can learn how to write Pcap4J programs from [samples](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-sample/src/main/java/org/pcap4j/sample).

Learn more about Pcap4j from the following documents:

* [Learn about packet class](/www/Packet.md)
* [Learn about Packet Factory](/www/PacketFactory.md)
* [How to add protocol support](/www/HowToAddProtocolSupport.md)
* [kaitoy's blog](http://tbd.kaitoy.xyz/tags/pcap4j/)

#### How to run samples ####
See the following examples:

* [org.pcap4j.sample.Loop](/www/sample_Loop.md)
* [org.pcap4j.sample.SendArpRequest](/www/sample_SendArpRequest.md)

If you want to run a sample in pcap4j-sample on Eclipse,
add pcap4j-packetfactory-static or pcap4j-packetfactory-propertiesbased project
to the top of User Entries in Classpath tab of the Run Configuration for the sample.

#### How to use in Maven project ####
Add a dependency to the pom.xml as like below:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                      http://maven.apache.org/xsd/maven-4.0.0.xsd">
  ...
  <dependencies>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-core</artifactId>
      <version>1.6.1</version>
    </dependency>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-packetfactory-static</artifactId>
      <version>1.6.1</version>
    </dependency>
       ...
  </dependencies>
  ...
</project>
```

#### About pcap library loading ####
By default, Pcap4j loads the pcap library on the following conditions:

* Windows
    * search path: The paths in the `PATH` environment variable.
    * file name: wpcap.dll
* Linux/UNIX
    * search path: The search paths of shared libraries configured on the OS.
      (e.g. The paths in the `LD_LIBRARY_PATH` environment variable)
    * file name: libpcap.so
* Mac OS X
    * search path: The search paths of shared libraries configured on the OS.
      (e.g. The paths in the `DYLD_LIBRARY_PATH` environment variable)
    * file name: libpcap.dylib

You can use the following Java system properties to change the default behavior.

* jna.library.path: Specify the search path
* org.pcap4j.core.pcapLibName: Specify the full path of the pcap library

### Docker ###
A Docker image for Pcap4J on CentOS is available at [Docker Hub](https://registry.hub.docker.com/u/kaitoy/pcap4j/).

Download it by `docker pull kaitoy/pcap4j` and execute `docker run kaitoy/pcap4j:latest` to start capturing packets from eth0 on the container.

This image is built everytime a commit is made on the Git repositry.

How to build
------------
I'm developing Pcap4j in the following environment.

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1 ([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717
* [Apache Maven](http://maven.apache.org/) 3.0.5

#### Build procedure with Maven command (recommended) ####
1. Install WinPcap or libpcap:<br>
   Install WinPcap (if Windows) or libpcap (if Linux/UNIX).
   It's needed for the unit tests which are run during a build.
2. Install JDK 1.6+:<br>
   Download and install JDK 1.6 (or newer), and set the environment variable ***JAVA_HOME*** properly.
3. Install Maven<br>
   Download and install Maven 3.0.5 (or newer).
   Then, add the path of the Maven bin directory to the environment variable ***PATH***.
4. Install Git:<br>
   Download [Git](http://git-scm.com/downloads) and install it.
   This step is optional.
5. Clone the Pcap4J repository:<br>
   If you installed Git, execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`<br>
   Otherwise, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/master) and extract it.
6. Build:<br>
   Open a command prompt/a terminal, `cd` to the project root directory,
   and execute `mvn install`.
   Note Administrator/root privileges are needed for the unit tests.

#### Build procedure on Eclipse ####
1. Install WinPcap or libpcap:<br>
   Install WinPcap (if Windows) or libpcap (if Linux/UNIX).
   It's needed for the unit tests which are run during a build.
2. Setup Eclipse 3.7+:<br>
   Install JDK for Eclipse.
   Then download an archived ***Eclipse IDE for Java Developers*** from
   [Eclipse.org](http://www.eclipse.org/downloads/), and extract it.
3. Install M2E:<br>
   Launch the Eclipse and select ***Help > Install New Software*** to open the install wizard.
   In the wizard window, enter the URL http://download.eclipse.org/technology/m2e/releases
   into the text field next to ***Work with:***, and press the enter key to start searching.
   When the search is done, check the the check box which precedes ***Maven Integration for Eclipse***,
   click the ***Next*** button, and follow the wizard instructions to complete the installation.
4. Install Git:<br>
   Download [Git](http://git-scm.com/downloads) and install it.
   This step is optional.
5. Clone the Pcap4J repository:<br>
   If you installed Git, execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`<br>
   Otherwise, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/master) and extract it.
6. Import the project into Eclipse:<br>
   In the Eclipse, select ***File > Import*** to open the import wizard.
   Then, select ***General > Existing Projects into Workspace*** and
   follow the wizard instructions to import all Pcap4J projects.
7. Build:<br>
   In the Eclipse, right-click the parent project in the ***Project Explorer*** and select ***Run as > Maven install***.
   Note Administrator/root privileges are needed for the unit tests.

For your information, M2E was formerly called [m2eclipse](http://m2eclipse.sonatype.org/).
If you want to build Pcap4j with m2eclipse, skip the step 2 and import the maven project instead of the eclipse project in the step 4.

License
-------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2015 Pcap4J.org

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
    NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contacts
--------

Kaito Yamada (kaitoy@pcap4j.org)

Extra
-----

An SNMP Network Simulator using Pcap4J; SNeO is also hosted on Github: https://github.com/kaitoy/sneo
