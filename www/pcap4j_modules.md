Pcap4j modules
--------------

Pcap4j consists of the following modules:

* pcap4j-core: The core module which includes pcap API wrappers, packet classes, and so on.
* pcap4j-packetfactory-static: The Static Packet Factory module.
* pcap4j-packetfactory-propertiesbased: The Properties-Based Packet Factory module.
* pcap4j-sample: The sample module.
* pcap4j-packettest: The module including test cases for packet classes.
* pcap4j-distribution: The distribution module.

pcap4j-core is always needed.

pcap4j-packetfactory-static and pcap4j-packetfactory-propertiesbased are Packet Factory modules.
Either of them is needed for packet analysis. Without Packet Factory modules, Pcap4J always returns a [UnknownPacket](https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/packet/UnknownPacket.java) object when it captures a packet.
Learn more about Packet Factory [here](/www/PacketFactory.md).

The other modules are not needed when you run your Pcap4J application.
