Packet Factory
==============

Packet Factory is used by the Pcap4J core module to create packet objects from captured packets (byte arrays).

Packet Factory is pluggable. This pluggability is made by the [Packet Factory Binder](#packet-factory-binder).

Pcap4J has two Packet Factory modules, [Static Packet Factory](#static-packet-factory) and [Properties-Based Packet Factory](#properties-based-packet-factory).

### Packet Factory Binder ###
Packet Factory Binder binds Packet Factory implementations to the Pcap4J core module.
Pcap4J core module's source includes [the interface of Packet Factory Binder](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/factory/PacketFactoryBinder.java).
An implementation of Packet Factory Binder is included in a Packet Factory module which also has Packet Factory implementations.

A Packet Factory implementation is used to find a packet class (e.g. [IpV4Packet](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/IpV4Packet.java))
or a packet piece class (e.g. [IpV4Rfc1349Tos](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/IpV4Rfc1349Tos.java))
by a classifier (e.g. [EtherType](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/namednumber/EtherType.java))
and to instantiate its object.

### Static Packet Factory ###
Static Packet Factory is a Packet Factory module including Packet Factory implementations which find packet and packet piece classes in static way,
which means you can't replace these classes without code changes.
This Packet Factory doesn't use Java reflection and so relatively faster than [Properties-Based Packet Factory](#properties-based-packet-factory).

<img alt="Static Packet Factory" title="Static Packet Factory" src="https://github.com/kaitoy/pcap4j/raw/v1/www/images/staticPacketFactory.png" />

### Properties-Based Packet Factory ###
Properties-Based Packet Factory is a Packet Factory module including Packet Factory implementations which find packet and packet piece classes by Java properties.
This Packet Factory heavily uses Java reflection and so relatively slower than [Static Packet Factory](#static-packet-factory).

<img alt="Properties-Based Packet Factory" title="Properties-Based Packet Factory" src="https://github.com/kaitoy/pcap4j/raw/v1/www/images/propertiesBasedPacketFactory.png" />
