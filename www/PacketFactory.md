Packet Factory
==============

<h3 id="static_packet_factory">PacketFactoryBinder</h3>
[PacketFactoryBinder](https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/packet/factory/PacketFactoryBinder.java)
is similar to StaticLoggerBinder of SLF4J.
It binds [PacketFactory](https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/packet/factory/PacketFactory.java) implementations to the Pcap4J Core module.

PacketFactory implementations are used to instantiate
Packet classes (e.g. [EthernetPacket](https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/packet/EthernetPacket.java))
and packet piese classes (e.g. [IpV4Rfc1349Tos](https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/packet/IpV4Rfc1349Tos.java))
included in Pcap4J Core module, namely pcap4j-core.jar.

PacketFactoryBinder class is included in Pcap4J Core module source but it is a dummy and removed in the assembry process.
Actual PacketFactoryBinder class is in Static Packet Factory module (pcap4j-packetfactory-static.jar) and Properties-Based Packet Factory (pcap4j-packetfactory-propertiesbased.jar),
which also include PacketFactory implementations.

<h3 id="static_packet_factory">Static Packet Factory</h3>
<img alt="Static Packet Factory" title="Static Packet Factory" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/staticPacketFactory.png" />

<h3 id="properties_based_packet_factory">Properties-Based Packet Factory</h3>
<img alt="Properties-Based Packet Factory" title="Properties-Based Packet Factory" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/propertiesBasedPacketFactory.png" />

