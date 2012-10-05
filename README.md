Pcap4J
======

Pcap4J is a Java library for capturing, crafting and sending packets.
Pcap4J wraps a native packet capture library([libpcap](http://www.tcpdump.org/) or
[WinPcap](http://www.winpcap.org/)) via [JNA](https://github.com/twall/jna)
and provides you Java-Oriented APIs.

Download
--------

Pcap4J 0.9.13

* [pcap4j.jar](/downloads/kaitoy/pcap4j/pcap4j.jar)

Why Pcap4J was born
--------
I have been developing an SNMP network simulator(SNeO, downloadable below) by Java.
During the development, I got need to capture packets, and I found that the pcap API is useful for it.
Although there are some implementations of pcap API; libpcap for UNIX and WinPcap for Windows,
because they are both native libraries, a Java wrapper library is necessary in order to use them for SNeO.
I searched it and found three Java wrapper libraries for pcap; [jpcap](http://jpcap.sourceforge.net/),
[jNetPcap](http://jnetpcap.com/), and [Jpcap](http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/).
But both jpcap and jNetPcap are unsuitable for SNeO because they seem to be designed for mainly capturing packets
and not to be much useful for making and sending packets. On the other hand, Jpcap is useful for
making and sending packets. But it has a defect in capturing ICMP packets and
it has already stopped updating long ago.
So I decided to develop Pcap4j.

Features
-------

* Capturing packets via a network interface and converting them into Java objects.
  You can access the packet objects to obtain fields of packets.
  You can also craft packets objects as you like.
* Sending packet objects to real network.
* Implementations for Ethernet, IEEE802.1Q, ARP, IPv4(RFC791 and RFC1349), IPv6(RFC2460), ICMPv4(RFC792), TCP(RFC793), and UDP.
* All packet classes are serializable and thread-safe(practically immutable).
* Pluggable packet classes.
* Dumping and reading pcap-formatted files(e.g. capture file of Wireshark)

Supported Operating Systems 
---------------------------

I tested Pcap4j on the following OSes with x86 processors.

* Windows: XP, Vista, 7, 2003 R2, 2008, 2008 R2, and 2012
* Linux
 * RHEL: 5 and 6
 * CentOS: 5
* UNIX
 * Solaris: 10

I believe Pcap4j can run on the other OSes supported by both JNA and libpcap.

How to use
----------

The JavaDoc is [here](http://kaitoy.github.com/pcap4j/0.9.13/javadoc/).


The documentation is in progress. You may know how to use Pcap4J from
[the documents of libpcap](http://www.tcpdump.org/pcap.html)(or WinPcap)
and [sample classes](/kaitoy/pcap4j/tree/master/src/main/java/org/pcap4j/sample).
The APIs are not stable yet and may be changed without announcement.
This library works with J2SE 5.0+, libpcap 0.9.3+ or WinPcap 3.0+, jna, slf4j-api,
and an implementation of logger.
I'm using the following libraries for the test.

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.3.0
* slf4j-api 1.6.4
* logback-core 1.0.1
* logback-classic 1.0.1

#### About pcap library loading ####
As the default, Pcap4j loads the pcap library on the following conditions.

* Windows
 * search path: The paths in the `PATH` environment variable.
 * file name: wpcap.dll
* Linux/UNIX
 * search path: The search paths of shared libraries configured on the OS.
   (e.g. The paths in the `LD_LIBRARY_PATH` environment variable)
 * file name: libpcap.so

You can use the following Java System Properties to change the default behavior.

* jna.library.path: Specify the serch path
* org.pcap4j.core.pcapLibName: Specify the full path of the pcap library

Samples
--------

* [org.pcap4j.sample.Loop](/kaitoy/pcap4j/blob/master/src/main/java/org/pcap4j/sample/Loop.java)<br>
  A sample which captures packets and dumps them.
  In the following box, you can see an example of running this sample to capture two ICMP packets via eth2 on Linux.


        [root@localhost Desktop]# java -cp pcap4j.jar:jna-3.3.0.jar:slf4j-api-1.6.4.jar -Dorg.pcap4j.sample.Loop.count=2 org.pcap4j.sample.Loop icmp
        org.pcap4j.sample.Loop.count: 2
        org.pcap4j.sample.Loop.readTimeout: 10
        org.pcap4j.sample.Loop.maxCapLen: 65536


        SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
        SLF4J: Defaulting to no-operation (NOP) logger implementation
        SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
        NIF[0]: eth0
              : description: null
              : address: /192.168.209.128
        NIF[1]: eth1
              : description: null
              : address: /192.168.76.128
        NIF[2]: eth2
              : description: null
              : address: /192.168.2.109
        NIF[3]: any
              : description: Pseudo-device that captures on all interfaces
        NIF[4]: lo
              : description: null
              : address: /127.0.0.1

        Select a device number to capture packets, or enter 'q' to quit > 2
        eth2(null)
        2012-10-05 03:48:51.881454
        [Ethernet Header (14 bytes)]
          Destination address: 00:0c:29:02:65:62
          Source address: 04:7d:7b:4c:2f:0a
          Type: 0x0800(IPv4)
        [IPv4 Header (20 bytes)]
          Version: 4(IPv4)
          IHL: 5 (20 [bytes])
          TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
          Total length: 60 [bytes]
          Identification: 3340
          Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
          Flagment offset: 0 (0 [bytes])
          TTL: 128
          Protocol: 1(ICMPv4)
          Header checksum: 0xa792
          Source address: /192.168.2.101
          Destination address: /192.168.2.109
        [ICMP Common Header (4 bytes)]
          Type: 8(Echo)
          Code: 0(No Code)
          Checksum: 0x4c53
        [ICMPv4 Echo Header (4 bytes)]
          Identifier: 256
          SequenceNumber: 9
        [data (32 bytes)]
          Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69

        2012-10-05 03:48:51.979233
        [Ethernet Header (14 bytes)]
          Destination address: 04:7d:7b:4c:2f:0a
          Source address: 00:0c:29:02:65:62
          Type: 0x0800(IPv4)
        [IPv4 Header (20 bytes)]
          Version: 4(IPv4)
          IHL: 5 (20 [bytes])
          TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
          Total length: 60 [bytes]
          Identification: 19161
          Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
          Flagment offset: 0 (0 [bytes])
          TTL: 64
          Protocol: 1(ICMPv4)
          Header checksum: 0xa9c5
          Source address: /192.168.2.109
          Destination address: /192.168.2.101
        [ICMP Common Header (4 bytes)]
          Type: 0(Echo Reply)
          Code: 0(No Code)
          Checksum: 0x5453
        [ICMPv4 Echo Reply Header (4 bytes)]
          Identifier: 256
          SequenceNumber: 9
        [data (32 bytes)]
          Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69

* [org.pcap4j.sample.SendArpRequest](/kaitoy/pcap4j/blob/master/src/main/java/org/pcap4j/sample/SendArpRequest.java)<br>
  A sample which sends ARP request and resolves an IP address to a MAC address.
  In the following box, you can see an example of running this sample to resolve 192.168.209.1 on Linux.


        [root@localhost Desktop]# java -cp pcap4j.jar:jna-3.3.0.jar:slf4j-api-1.6.4.jar -Dorg.pcap4j.sample.Loop.count=2 org.pcap4j.sample.SendArpRequest 192.168.209.1
        org.pcap4j.sample.SendArpRequest.count: 1
        org.pcap4j.sample.SendArpRequest.readTimeout: 10
        org.pcap4j.sample.SendArpRequest.maxCapLen: 65536


        SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
        SLF4J: Defaulting to no-operation (NOP) logger implementation
        SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
        NIF[0]: eth0
              : description: null
              : address: /192.168.209.128
        NIF[1]: eth1
              : description: null
              : address: /192.168.76.128
        NIF[2]: eth2
              : description: null
              : address: /192.168.2.109
        NIF[3]: any
              : description: Pseudo-device that captures on all interfaces
        NIF[4]: lo
              : description: null
              : address: /127.0.0.1

        Select a device number to capture packets, or enter 'q' to quit > 0
        eth0(null)
        [Ethernet Header (14 bytes)]
          Destination address: ff:ff:ff:ff:ff:ff
          Source address: fe:00:01:02:03:04
          Type: 0x0806(ARP)
        [ARP Header (28 bytes)]
          Hardware type: 1(Ethernet(10Mb))
          Protocol type: 0x0800(IPv4)
          Hardware length: 6 [bytes]
          Protocol length: 4 [bytes]
          Operation: 1(REQUEST)
          Source hardware address: fe:00:01:02:03:04
          Source protocol address: /192.0.2.100
          Destination hardware address: ff:ff:ff:ff:ff:ff
          Destination protocol address: /192.168.209.1
        [Ethernet Pad (18 bytes)]
          Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        [Ethernet Header (14 bytes)]
          Destination address: fe:00:01:02:03:04
          Source address: 00:50:56:c0:00:08
          Type: 0x0806(ARP)
        [ARP Header (28 bytes)]
          Hardware type: 1(Ethernet(10Mb))
          Protocol type: 0x0800(IPv4)
          Hardware length: 6 [bytes]
          Protocol length: 4 [bytes]
          Operation: 2(REPLY)
          Source hardware address: 00:50:56:c0:00:08
          Source protocol address: /192.168.209.1
          Destination hardware address: fe:00:01:02:03:04
          Destination protocol address: /192.0.2.100
        [Ethernet Pad (18 bytes)]
          Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        192.168.209.1 was resolved to 00:50:56:c0:00:08


How to build
------------
I'm developing Pcap4j in the following environment.

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717

The build procedure is the following.

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
   If you skipped the step 3, download the repository as a [zip ball](https://github.com/kaitoy/pcap4j/zipball/master)
5. Import the Eclipse project<br>
   In the Eclipse, select [File] > [Import]  to open the "Import" wizard.
   Select [General] > [Existing Projects into Workspace] and
   follow the wizard to import the project in the Pcap4J repository.
6. Build<br>
   Right-click the Pcap4J project in the Project Explorer of Eclipse and select [Run as] > [Maven install]

For your information, M2E was formerly called [m2eclipse](http://m2eclipse.sonatype.org/).
If you want to build Pcap4j with m2eclipse, skip the step 2 and import the maven project instead of the eclipse project in the step 4.

License
-------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2012 Kaito Yamada
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

SNeO: an SNMP Network Simulator using Pcap4J 0.9.13 is available below. The documents will come someday.
You can use this version of SNeO in both personal and commercial for free. You can also copy and distribute it.

SNeO 1.0.11

* [sneo.jar](/downloads/Kaitoy/pcap4j/sneo.jar)
