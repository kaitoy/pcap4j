[Japanese](/README_ja.md)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/pcap4jlogo.png" height="217" width="667" />

Pcap4J
======

Pcap4J is a Java library for capturing, crafting and sending packets.
Pcap4J wraps a native packet capture library([libpcap](http://www.tcpdump.org/) or
[WinPcap](http://www.winpcap.org/)) via [JNA](https://github.com/twall/jna)
and provides you Java-Oriented APIs.

Download
--------

Pcap4J is now available on the Maven Central Repository.

Pcap4J 0.9.13 (last version distributed from this page)

* [pcap4j.jar](https://github.com/downloads/kaitoy/pcap4j/pcap4j.jar)

Pcap4J 1.1.0 (latest version on Maven Central Repository)

* without source: [pcap4j-distribution-1.1.0-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.1.0/pcap4j-distribution-1.1.0-bin.zip)
* with    source: [pcap4j-distribution-1.1.0-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.1.0/pcap4j-distribution-1.1.0-src.zip)

Why Pcap4J was born
--------
I have been developing an SNMP network simulator(SNeO, available at the link below) by Java,
which needed to capture packets and I found the [pcap](http://en.wikipedia.org/wiki/Pcap) was useful for it.
Although there are some implementations of the pcap such as libpcap(for UNIX) and WinPcap(for Windows),
because they are both native libraries, a Java wrapper library was necessary in order to use them for SNeO.
I researched it and found three Java wrapper libraries for pcap: [jpcap](http://jpcap.sourceforge.net/),
[jNetPcap](http://jnetpcap.com/), and [Jpcap](http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/).
But both jpcap and jNetPcap were unsuitable for SNeO because they seemed to be designed for mainly capturing packets
and not to be useful for making and sending packets so much. On the other hand, Jpcap looked useful for
making and sending packets. But it had a defect in capturing ICMP packets and
its development seemed to be stopped long ago.
That's why I started developing Pcap4j.

Features
-------

* Capturing packets via a network interface and converting them into Java objects.
  You can get/set each field of a packet header via the Java object converted from the packet.
  You can also craft a packet object from scratch.
* Sending packet objects to a real network.
* Supported protocols: Ethernet, IEEE802.1Q, ARP, IPv4(RFC791 and RFC1349), IPv6(RFC2460), ICMPv4(RFC792), ICMPv6(RFC4443, RFC4861), TCP(RFC793), and UDP.
* All built-in packet classes are serializable and thread-safe(practically immutable).
* You can add a protocol support without modifying Pcap4J library itself.
* Dumping and reading pcap-formatted files(e.g. a capture file of Wireshark).

Supported Operating Systems
---------------------------

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

How to use
----------

The latest JavaDoc is [here](http://kaitoy.github.com/pcap4j/javadoc/latest/en).
Each version's JavaDoc is on the [Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22).
The version 0.9.13's JavaDoc is [here](http://kaitoy.github.com/pcap4j/javadoc/0.9.13/en).

And the following resources will help you to learn how to use Pcap4j.

* [Documents of libpcap](http://www.tcpdump.org/pcap.html)
* [Documents of WinPcap](http://www.winpcap.org/docs/default.htm)
* [Mapping between pcap API and Pcap4j API](/www/api_mappings.md)
* [Learn About Packet](/www/Packet.md)
* [Learn About Packet Factory](/www/PacketFactory.md)
* [Test Classes](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-packettest/src/test/java/org/pcap4j/packet)
* [Sample Classes](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-sample/src/main/java/org/pcap4j/sample)
* [How to add protocol support](/www/HowToAddProtocolSupport.md)

Pcap4j 1.1.0 or older needs J2SE 5.0+. Pcap4j 1.2.0 or older needs J2SE 6.0+.
And also libpcap 0.9.3+ or WinPcap 3.0+, jna, slf4j-api, and an implementation of logger for slf4j are required.
I'm using the following libraries for the test.

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.5.2
* slf4j-api 1.6.4
* logback-core 1.0.1
* logback-classic 1.0.1

Run Pcap4J with administrator/root privileges.

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


#### How to use in a Maven project ####
Add a dependency to the pom.xml as like below:

      <project xmlns="http://maven.apache.org/POM/4.0.0"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                            http://maven.apache.org/xsd/maven-4.0.0.xsd">
        ...
        <dependencies>
          <dependency>
            <groupId>org.pcap4j</groupId>
            <artifactId>pcap4j-core</artifactId>
            <version>1.1.0</version>
          </dependency>
          <dependency>
            <groupId>org.pcap4j</groupId>
            <artifactId>pcap4j-packetfactory-static</artifactId>
            <version>1.1.0</version>
          </dependency>
             ...
        </dependencies>
        ...
      </project>


Examples
--------

* [org.pcap4j.sample.Loop](/www/sample_Loop.md)
* [org.pcap4j.sample.SendArpRequest](/www/sample_SendArpRequest.md)


How to build
------------
I'm developing Pcap4j in the following environment.

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717
* [Apache Maven](http://maven.apache.org/) 3.0.5

The build procedure using Eclipse is the following:

0. Install WinPcap/libpcap<br>
   The pcap library is needed for the unit tests ran in the Build step.
1. Setup Eclipse 3.7+<br>
   Install JDK, download a compressed Eclipse file from
   the [Eclipse Downloads Page](http://www.eclipse.org/downloads/), and decompress it.
2. Install M2E<br>
   Launch the Eclipse and select Help > Install New Software to open the "Install" wizard.
   Paste the Update Site URL(http://download.eclipse.org/technology/m2e/releases)
   into the field named "Work with:" and press Enter.
   Click and check the box of "Maven Integration for Eclipse".
   Click Next or Finish until beginning of the installation process.
   Once the installation process is finished, restart the Eclipse.
3. Install Git<br>
   Download [Git](http://git-scm.com/downloads) and install it.
   This step is optional, you can skip this step.
4. Clone the Pcap4J repository<br>
   Execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`<br>
   If you skipped the step 3, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/master) and extract it.
5. Import the Eclipse project<br>
   In the Eclipse, select [File] > [Import]  to open the "Import" wizard.
   Select [General] > [Existing Projects into Workspace] and
   follow the wizard to import the all projects in the Pcap4J repository.
6. Build<br>
   Right-click the parent project in the Project Explorer of Eclipse and select [Run as] > [Maven install].
   Note administrator/root privileges are needed for the unit tests.

For your information, M2E was formerly called [m2eclipse](http://m2eclipse.sonatype.org/).
If you want to build Pcap4j with m2eclipse, skip the step 2 and import the maven project instead of the eclipse project in the step 4.

The build procedure using Maven command line is the following:

0. Install WinPcap/libpcap<br>
   The pcap library is needed for the unit tests ran in the Build step.
1. Install JDK1.5+<br>
   Set the environment variable JAVA_HOME properly.
2. Install Maven<br>
   The newer the better. Add the path of the Maven bin directory to the environment variable PATH.
3. Install Git<br>
   Download [Git](http://git-scm.com/downloads) and install it.
   This step is optional, you can skip this step.
4. Clone the Pcap4J repository<br>
   Execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`<br>
   If you skipped the step 3, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/master) and extract it.
5. Build<br>
   Open a command prompt, `cd` to the project root directory(i.e. the same directory as the pom.xml in the directory created in the step 4),
   and execute `mvn install`.
   Note administrator/root privileges are needed for the unit tests.

License
-------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2013 Kaito Yamada
    All rights reserved.

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

Extra
-----

An SNMP Network Simulator using Pcap4J; SNeO is also hosted on Github: https://github.com/kaitoy/sneo

