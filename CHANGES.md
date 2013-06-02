Next Release
============
### New Features ###

### Bug Fixes ###
* Fix org.pcap4j.packet.IpV6NeighborDiscoveryPrefixInformationOption#getRawData() to return correct prefixLength.

### Other Changes ###

Release 0.9.15 (29-May-2013)
============
### New Features ###
* Add ICMPv6(RFC4443, RFC4861) support.

### Bug Fixes ###
* [Issues#7](https://github.com/kaitoy/pcap4j/issues/7): Fix invalid properties in packet.properties. - [@kaitoy](https://github.com/kaitoy)

### Other Changes ###
* Change class names
 * org.pcap4j.core.PcapIpv4Address -> org.pcap4j.core.PcapIpV4Address
 * org.pcap4j.core.PcapIpv6Address -> org.pcap4j.core.PcapIpV6Address
* Change property names
 * org.pcap4j.packet.icmpv4.calcChecksumAtBuild -> org.pcap4j.packet.icmpV4.calcChecksumAtBuild
 * org.pcap4j.packet.ipv4.calcChecksumAtBuild -> org.pcap4j.packet.ipV4.calcChecksumAtBuild
 * org.pcap4j.packet.tcpv4.calcChecksumAtBuild -> org.pcap4j.packet.tcpV4.calcChecksumAtBuild
 * org.pcap4j.packet.udpv4.calcChecksumAtBuild -> org.pcap4j.packet.udpV4.calcChecksumAtBuild
 * org.pcap4j.packet.tcpv6.calcChecksumAtBuild -> org.pcap4j.packet.tcpV6.calcChecksumAtBuild
 * org.pcap4j.packet.udpv6.calcChecksumAtBuild -> org.pcap4j.packet.udpV6.calcChecksumAtBuild
* Change serialization formats
 * org.pcap4j.packet.IcmpV4CommonPacket
 * org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader
 * org.pcap4j.packet.IcmpV4DestinationUnreachablePacket
 * org.pcap4j.packet.IcmpV4DestinationUnreachablePacket.IcmpV4DestinationUnreachableHeader
 * org.pcap4j.packet.IcmpV4ParameterProblemPacket
 * org.pcap4j.packet.IcmpV4ParameterProblemPacket.IcmpV4ParameterProblemHeader
 * org.pcap4j.packet.IcmpV4RedirectPacket
 * org.pcap4j.packet.IcmpV4RedirectPacket.IcmpV4RedirectHeader
 * org.pcap4j.packet.IcmpV4SourceQuenchPacket
 * org.pcap4j.packet.IcmpV4SourceQuenchPacket.IcmpV4SourceQuenchHeader
 * org.pcap4j.packet.IcmpV4TimeExceededPacket
 * org.pcap4j.packet.IcmpV4TimeExceededPacket.IcmpV4TimeExceededHeader
* Move invoking packet from header to payload
 * org.pcap4j.packet.IcmpV4DestinationUnreachablePacket
 * org.pcap4j.packet.IcmpV4ParameterProblemPacket
 * org.pcap4j.packet.IcmpV4RedirectPacket
 * org.pcap4j.packet.IcmpV4SourceQuenchPacket
 * org.pcap4j.packet.IcmpV4TimeExceededPacket
 
Release 0.9.14 (13-Apr-2013)
=====================
### New Features ###
* The first release to the Maven Central Repository.
* [Issues#4](https://github.com/kaitoy/pcap4j/issues/4): JNA 3.5+ Support. - [@kaitoy](https://github.com/kaitoy)

### Bug Fixes ###

