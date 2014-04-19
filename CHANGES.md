Future
======
### New Features ###
* Add SSH2 support.
* Upgrade JNA to 4.10.

### Bug Fixes ###

### Other Changes ###
* Required Java version changes from 5 to 6.

Release 1.1.0 (7-Mar-2014)
==========================
### New Features ###
* Add FreeBSD support.
* Mac address discovery on Linux, Mac OS X, and FreeBSD.
* Add properties; org.pcap4j.af.inet, org.pcap4j.af.inet6, org.pcap4j.af.packet and org.pcap4j.af.link to specify address family numbers.

### Bug Fixes ###
* Correct IP address discovery on Mac OS X.

### Other Changes ###
* Change org.pcap4j.packet.AbstractPacket.measureLength() to org.pcap4j.packet.AbstractPacket.calcLength()
* Change org.pcap4j.packet.AbstractPacket.AbstractHeader.measureLength() to org.pcap4j.packet.AbstractPacket.AbstractHeader.calcLength()
* Change the return value of org.pcap4j.util.PropertiesLoader#getInteger() from int to Integer.
* Change serialization formats:
 * org.pcap4j.util.MacAddress

Release 1.0.0 (20-Jun-2013)
===========================
### New Features ###
* Add pcap APIs support: pcap_setnonblock, pcap_getnonblock, lookupNet, dispatch, pcap_compile_nopcap,
                         pcap_compile, pcap_freecode, pcap_snapshot, pcap_is_swapped, pcap_major_version,
                         pcap_minor_version, pcap_stats, pcap_dump_ftell, pcap_list_datalinks,
                         pcap_free_datalinks, pcap_set_datalink, pcap_datalink_name_to_val,
                         pcap_datalink_val_to_name, pcap_datalink_val_to_description, pcap_strerror,
                         pcap_lib_version, pcap_dump_flush
* Add Ubuntu support.
* Add getReturnCode method to PcapNativeException.
* [Issues#3](https://github.com/kaitoy/pcap4j/issues/3): Change to a multi-module project.

### Bug Fixes ###
* Fix org.pcap4j.packet.IpV6NeighborDiscoveryPrefixInformationOption#getRawData() to return correct prefixLength.
* Fix invalid properties for IPv4 Internet TimestampOption.
* Fix org.pcap4j.core.Pcaps.openDead() to return opened PcapHandle.

### Other Changes ###
* Modify org.pcap4j.core.PcapHandle and org.pcap4j.core.PcapDumper to throw NotOpenException instead of IllegalStateException.
* Change a package of class: org.pcap4j.core.PcapHandle.BpfCompileMode -> org.pcap4j.core.BpfProgram.BpfCompileMode
* Change class names:
 * org.pcap4j.packet.UnknownIpV4InternetTimestampData -> org.pcap4j.packet.UnknownIpV4InternetTimestampOptionData
 * org.pcap4j.packet.factory.PropertiesBasedIpV4InternetTimestampDataFactory -> org.pcap4j.packet.factory.PropertiesBasedIpV4InternetTimestampOptionDataFactory
* Change method names:
 * org.pcap4j.core.Pcaps.getNifByName(String) -> org.pcap4j.core.Pcaps.getDevByName(String)
 * org.pcap4j.core.Pcaps.getNifByAddress(InetAddress) -> org.pcap4j.core.Pcaps.getDevByAddress(InetAddress)
* Delete obsolete classes:
 * org.pcap4j.packet.factory.IpV4TosFactories
 * org.pcap4j.packet.factory.IpV4TosFactory
 * org.pcap4j.packet.factory.IpV6FlowLabelFactories
 * org.pcap4j.packet.factory.IpV6FlowLabelFactory
 * org.pcap4j.packet.factory.IpV6TrafficClassFactories
 * org.pcap4j.packet.factory.IpV6TrafficClassFactory
 * org.pcap4j.packet.factory.ClassifiedDataFactories
 * org.pcap4j.packet.factory.ClassifiedDataFactoriy

Release 0.9.15 (29-May-2013)
============================
### New Features ###
* Add ICMPv6(RFC4443, RFC4861) support.

### Bug Fixes ###
* [Issues#7](https://github.com/kaitoy/pcap4j/issues/7): Fix invalid properties in packet.properties. - [@kaitoy](https://github.com/kaitoy)

### Other Changes ###
* Change class names:
 * org.pcap4j.core.PcapIpv4Address -> org.pcap4j.core.PcapIpV4Address
 * org.pcap4j.core.PcapIpv6Address -> org.pcap4j.core.PcapIpV6Address
* Change property names:
 * org.pcap4j.packet.icmpv4.calcChecksumAtBuild -> org.pcap4j.packet.icmpV4.calcChecksumAtBuild
 * org.pcap4j.packet.ipv4.calcChecksumAtBuild -> org.pcap4j.packet.ipV4.calcChecksumAtBuild
 * org.pcap4j.packet.tcpv4.calcChecksumAtBuild -> org.pcap4j.packet.tcpV4.calcChecksumAtBuild
 * org.pcap4j.packet.udpv4.calcChecksumAtBuild -> org.pcap4j.packet.udpV4.calcChecksumAtBuild
 * org.pcap4j.packet.tcpv6.calcChecksumAtBuild -> org.pcap4j.packet.tcpV6.calcChecksumAtBuild
 * org.pcap4j.packet.udpv6.calcChecksumAtBuild -> org.pcap4j.packet.udpV6.calcChecksumAtBuild
* Change serialization formats:
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
* Move invoking packet from header to payload:
 * org.pcap4j.packet.IcmpV4DestinationUnreachablePacket
 * org.pcap4j.packet.IcmpV4ParameterProblemPacket
 * org.pcap4j.packet.IcmpV4RedirectPacket
 * org.pcap4j.packet.IcmpV4SourceQuenchPacket
 * org.pcap4j.packet.IcmpV4TimeExceededPacket
 
Release 0.9.14 (13-Apr-2013)
============================
### New Features ###
* The first release to the Maven Central Repository.
* [Issues#4](https://github.com/kaitoy/pcap4j/issues/4): JNA 3.5+ Support. - [@kaitoy](https://github.com/kaitoy)

### Bug Fixes ###

