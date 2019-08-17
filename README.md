[Japanese](/README_ja.md)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/v1/www/images/logos/pcap4j-logo-color.png" width="70%" style="margin: 0px auto; display: block;" />

[Logos](https://github.com/kaitoy/pcap4j/blob/v1/www/logos.md)

[![Slack](http://pcap4j-slackin.herokuapp.com/badge.svg)](https://pcap4j-slackin.herokuapp.com/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution)

[![Build Status](https://travis-ci.org/kaitoy/pcap4j.svg?branch=v1)](https://travis-ci.org/kaitoy/pcap4j)
[![CircleCI](https://circleci.com/gh/kaitoy/pcap4j/tree/v1.svg?style=svg)](https://circleci.com/gh/kaitoy/pcap4j/tree/v1)
[![Build status](https://ci.appveyor.com/api/projects/status/github/kaitoy/pcap4j?branch=v1&svg=true)](https://ci.appveyor.com/project/kaitoy/pcap4j/branch/v1)
[![Coverage Status](https://coveralls.io/repos/kaitoy/pcap4j/badge.svg)](https://coveralls.io/r/kaitoy/pcap4j)
[![Code Quality: Java](https://img.shields.io/lgtm/grade/java/g/kaitoy/pcap4j.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/kaitoy/pcap4j/context:java)
[![Total Alerts](https://img.shields.io/lgtm/alerts/g/kaitoy/pcap4j.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/kaitoy/pcap4j/alerts)

Pcap4J
======

Pcap4J is a Java library for capturing, crafting and sending packets.
Pcap4J wraps a native packet capture library ([libpcap](http://www.tcpdump.org/),
[WinPcap](http://www.winpcap.org/), or [Npcap](https://github.com/nmap/npcap)) via [JNA](https://github.com/twall/jna)
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
    * [About native library loading](#about-native-library-loading)
        * [WinPcap or Npcap](#winpcap-or-npcap)
    * [Docker](#docker)
* [How to build](#how-to-build)
* [Contributing Code](#contributing-code)
* [License](#license)
* [Contacts](#contacts)

Download
--------

Pcap4J is available on the Maven Central Repository.

* Pcap4J 1.8.2
    * without source: [pcap4j-distribution-1.8.2-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.8.2/pcap4j-distribution-1.8.2-bin.zip)
    * with    source: [pcap4j-distribution-1.8.2-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.8.2/pcap4j-distribution-1.8.2-src.zip)
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
    * Ethernet, Linux SLL, raw IP, PPP (RFC1661, RFC1662), BSD (Mac OS X) loopback encapsulation, and Radiotap
    * IEEE 802.11
        * Probe Request
    * LLC and SNAP
    * IEEE802.1Q
    * ARP
    * IPv4 (RFC791 and RFC1349) and IPv6 (RFC2460)
    * ICMPv4 (RFC792) and ICMPv6 (RFC4443, RFC4861, and RFC6275)
    * TCP (RFC793, RFC2018, and draft-ietf-tcpm-1323bis-21), UDP, and SCTP (only common header)
    * GTPv1 (only GTP-U and GTP-C header)
    * DNS (RFC1035, RFC3596, and RFC6844)
* All built-in packet classes are serializable and thread-safe (practically immutable).
* You can add a protocol support without modifying Pcap4J library itself.
* Dumping and reading pcap-formatted files (e.g. a capture file of Wireshark).

How to use
----------

#### System requirements ####

##### Dependencies #####
Pcap4j 1.1.0 or older needs Java 5.0+. Pcap4j 1.2.0 or newer needs Java 6.0+.
And also a pcap native library (libpcap 1.0.0+, WinPcap 3.0+, or Npcap), jna, slf4j-api, and an implementation of logger for slf4j are required.
I'm using the following libraries for the test.

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 5.1.0
* slf4j-api 1.7.25
* logback-core 1.0.0
* logback-classic 1.0.0

##### Platforms #####
I tested Pcap4j on the following OSes with x86 or x64 processors.

* Windows: XP, Vista, 7, [10](http://tbd.kaitoy.xyz/2016/01/12/pcap4j-with-four-native-libraries-on-windows10/), 2003 R2, 2008, 2008 R2, and 2012
* Linux
    * RHEL: 5, 6, and 7
    * CentOS: 5, 6, and 7
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
The latest JavaDoc is [here](https://www.javadoc.io/doc/org.pcap4j/pcap4j-distribution/1.8.2).
Each version's JavaDoc is on the [Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22).

Refer to [here](https://github.com/kaitoy/pcap4j/blob/v1/www/pcap4j_modules.md) for information about Pcap4J modules.

Because Pcap4J is a wrapper of a pcap native library, the following documents help you to understand how to use Pcap4J.

* [Programming with pcap](http://www.tcpdump.org/pcap.html)
* [WinPcap Manuals](http://www.winpcap.org/docs/default.htm)
* [Mapping between pcap API and Pcap4J API](https://github.com/kaitoy/pcap4j/blob/v1/www/api_mappings.md)

You can learn how to write Pcap4J programs from [samples](https://github.com/kaitoy/pcap4j/tree/v1/pcap4j-sample/src/main/java/org/pcap4j/sample).

Learn more about Pcap4j from the following documents:

* [Learn about packet class](https://github.com/kaitoy/pcap4j/blob/v1/www/Packet.md)
* [Learn about Packet Factory](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md)
* [How to add protocol support](https://github.com/kaitoy/pcap4j/blob/v1/www/HowToAddProtocolSupport.md)
* [kaitoy's blog](http://tbd.kaitoy.xyz/tags/pcap4j/)

#### How to run samples ####
See the following examples:

* [org.pcap4j.sample.Loop](https://github.com/kaitoy/pcap4j/blob/v1/www/sample_Loop.md)
* [org.pcap4j.sample.SendArpRequest](https://github.com/kaitoy/pcap4j/blob/v1/www/sample_SendArpRequest.md)

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
      <version>1.8.2</version>
    </dependency>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-packetfactory-static</artifactId>
      <version>1.8.2</version>
    </dependency>
       ...
  </dependencies>
  ...
</project>
```

#### About native library loading ####
By default, Pcap4j loads the native libraries on the following conditions:

* Windows
    * search path: The paths in the `PATH` environment variable, etc. (See [MSDN](https://msdn.microsoft.com/en-us/library/7d83bc18.aspx) for the details.)
    * file name: wpcap.dll and Packet.dll
* Linux/UNIX
    * search path: The search paths of shared libraries configured on the OS.
      (e.g. The paths in the `LD_LIBRARY_PATH` environment variable)
    * file name: libpcap.so
* Mac OS X
    * search path: The search paths of shared libraries configured on the OS.
      (e.g. The paths in the `DYLD_LIBRARY_PATH` environment variable)
    * file name: libpcap.dylib

You can use the following Java system properties to change the default behavior.

* jna.library.path: The search path
* org.pcap4j.core.pcapLibName: The full path of the pcap library (wpcap.dll, libpcap.so, or libpcap.dylib)
* (Windows only) org.pcap4j.core.packetLibName: The full path of the packet library (Packet.dll)

##### WinPcap or Npcap #####
There are two native pcap libraries for Windows; WinPcap and Npcap.

The development of WinPcap has stopped since version 4.1.3 (libpcap 1.0.0 base) was released on 3/8/2013,
while Npcap is still being developed.
So, you should pick Npcap if you want to use new features or so.

Pcap4J can load WinPcap without tricks because it's installed in `%SystemRoot%\System32\`.

On the other hand, because Npcap is installed in `%SystemRoot%\System32\Npcap\` by default,
you need to do either of the following so that Pcap4J can load it:

* Add `%SystemRoot%\System32\Npcap\` to `PATH`.
* Set `jna.library.path` to `%SystemRoot%\System32\Npcap\`.
* Set `org.pcap4j.core.pcapLibName` to `%SystemRoot%\System32\Npcap\wpcap.dll` and
  `org.pcap4j.core.packetLibName` to `%SystemRoot%\System32\Npcap\Packet.dll`.
* Install Npcap with `WinPcap Compatible Mode` on.

### Docker ###

[![](https://images.microbadger.com/badges/image/kaitoy/pcap4j.svg)](https://microbadger.com/images/kaitoy/pcap4j)

A Docker image for Pcap4J on CentOS is available at [Docker Hub](https://registry.hub.docker.com/u/kaitoy/pcap4j/).

Download it by `docker pull kaitoy/pcap4j` and execute `docker run kaitoy/pcap4j:latest` to start capturing packets from eth0 on the container.

This image is built everytime a commit is made on the Git repositry.

How to build
------------

1. Install libpcap, WinPcap, or Npcap:

    Install WinPcap (if Windows) or libpcap (if Linux/UNIX).
    It's needed for the unit tests which are run during a build.

2. Install JDK:

    Download and install JDK 9, 10, or 11, and set the environment variable ***JAVA_HOME*** properly.

3. Add the JDK to [Maven toolchains](https://maven.apache.org/guides/mini/guide-using-toolchains.html):

    Create [toolchains.xml](https://maven.apache.org/ref/3.6.1/maven-core/toolchains.html) describing the JDK installed at the previous step and put it into `~/.m2/`.
    `toolchains.xml` is like below:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <toolchains xmlns="http://maven.apache.org/TOOLCHAINS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://maven.apache.org/TOOLCHAINS/1.1.0 http://maven.apache.org/xsd/toolchains-1.1.0.xsd">
      <toolchain>
        <type>jdk</type>
        <provides>
          <version>11</version>
        </provides>
        <configuration>
          <jdkHome>/path/to/jdk-11</jdkHome>
        </configuration>
      </toolchain>
    </toolchains>
    ```

4. Install Git:

    Download [Git](http://git-scm.com/downloads) and install it.
    This step is optional.

5. Clone the Pcap4J repository:

    If you installed Git, execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`<br>
    Otherwise, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/v1) and extract it.

6. Build:

    Open a command prompt/a terminal, `cd` to the project root directory, and execute `./mvnw install`.
    Note Administrator/root privileges are needed for the unit tests.

Contributing Code
-----------------

1. Fork this repository.
2. Create a branch from v1 branch.
3. Write code.

    * Please refer to [This PR](https://github.com/kaitoy/pcap4j/pull/70) as an example when adding protocol support.
    * This project follows [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html). Execute the following command to format your code: `mvnw com.coveo:fmt-maven-plugin:format`

4. Send a PR from the branch.

License
-------

[LICENSE](/LICENSE)

Contacts
--------

Kaito Yamada (kaitoy@pcap4j.org)
