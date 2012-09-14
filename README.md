Pcap4J
======

Pcap4J is a packet capture library for Java. You can also craft packets and send them with it.
Pcap4J wraps a native packet capture library([libpcap](http://www.tcpdump.org/) or
[WinPcap](http://www.winpcap.org/) via [JNA](https://github.com/twall/jna)
and provides you Java-Oriented APIs.

Download
--------

Pcap4J 0.9.11

* [pcap4j.jar](/downloads/Kaitoy/pcap4j/pcap4j.jar)

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

Feature
-------

* Capturing packets via a network interface and converting them into Java objects.
  You can access the packet objects to obtain fields of packets.
  You can also craft packets objects as you like.
* Sending packet objects to real network.
* Implementations for Ethernet, IEEE802.1Q, ARP, IPv4(RFC791 and RFC1349), IPv6(RFC2460), ICMPv4(RFC792), and UDP.
* All packet classes are serializable and thread-safe(practically immutable).
* Pluggable packet classes.
* Dumping and reading pcap-formatted files(e.g. capture file of Wireshark)


How to use
----------

Documentation is in progress. You may know how to use Pcap4J from
documents of libpcap(or WinPcap) and sample classes.
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
 * search path: The paths in the environmental variable; `PATH`.
 * file name: wpcap.dll
* Linux/UNIX
 * search path: The search paths of shared libraries configured on the OS.
   (e.g. The paths in the environmental variable; `LD_LIBRARY_PATH`)
 * file name: libpcap.so

You can use the following Java System Properties to change the default behavior.

* jna.library.path: Specify the serch path
* org.pcap4j.core.pcapLibName: Specify the full path of the pcap library

How to build
------------
I'm developing Pcap4j in the following environment.

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717

The build procedure is the following.

1. Setup Eclipse 3.7+
   Install JDK, download a compressed Eclipse file from
   the [Eclipse Downloads Page](http://www.eclipse.org/downloads/), and decompress it.
2. Install m2e
   Launch the Eclipse and select Help > Install New Software to open the "Install" wizard.
   Paste the Update Site URL(http://download.eclipse.org/technology/m2e/releases)
   into the field named "Work with:" and press Enter.
   Click and check the box of "Maven Integration for Eclipse".
   Click Next or Finish until beginning of the installation process.
   Once the installation process is finished, restart the Eclipse.
3. Install Git
   Download [Git[(http://git-scm.com/downloads) and install it.
4. Clone the Pcap4J repository
   Execute the following command: `git clone git@github.com:kaitoy/pcap4j.git`
5. Import the Eclipse project
   In the Eclipse, select [File] > [Import]  to open the "Import" wizard.
   Select [General] > [Existing Projects into Workspace] and
   follow the wizard to import the project in the Pcap4J repository.
6. Build
   Right-click the Pcap4J project in the Project Explorer of Eclipse and select [Run as] > [Maven install]

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

SNeO: an SNMP Network Simulator using Pcap4J 0.9.11 is available below. The documents will come someday.
You can use this version of SNeO in both personal and commercial for free. You can also copy and distribute it.

SNeO 1.0.10

* [sneo.jar](/downloads/Kaitoy/pcap4j/sneo.jar)
