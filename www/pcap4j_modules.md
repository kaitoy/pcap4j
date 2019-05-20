Pcap4j modules
--------------

Pcap4j consists of the following modules:

* pcap4j-core: The core module which includes pcap API wrappers, packet classes, and so on.

  module name: `org.pcap4j.core`
* pcap4j-packetfactory-static: [The Static Packet Factory](/www/PacketFactory.md#static-packet-factory) module.

  module name: `org.pcap4j.packetfactory.statik`
* pcap4j-packetfactory-propertiesbased: [The Properties-Based Packet Factory](/www/PacketFactory.md#properties-based-packet-factory) module.

  module name: `org.pcap4j.packetfactory.propertiesbased`
* pcap4j-sample: The sample module.

  module name: `org.pcap4j.sample`
* pcap4j-packettest: The module including test cases for packet classes.
  The tests are not run in this module. Instead, they are copied to pcap4j-packetfactory-static and
  pcap4j-packetfactory-propertiesbased and then run in the modules respectively.

  module name: `org.pcap4j.packettest`
* pcap4j-distribution: The distribution module.
  This module is not built unless the maven profile ***distribution-assembly*** is activated.
  To build Pcap4J with it activated, for example, execute `mvn -P distribution-assembly install`.
* pcap4j-test-coverage: The dummy module to measure test coverage of Pcap4J.
  This module is built when the maven profile ***test-coverage*** is activated.
  During a build, this module retrieves the source of pcap4j-core, pcap4j-packetfactory-static,
  and pcap4j-packettest to run tests included in pcap4j-packettest at one place, and then
  measure the test coverage of pcap4j-packettest with [JaCoCo](https://www.eclemma.org/jacoco/).

To run a Pcap4J application, pcap4j-core's artifact is always needed.

pcap4j-packetfactory-static and pcap4j-packetfactory-propertiesbased are Packet Factory modules.
An artifact of either of them is needed for packet analysis. Without Packet Factory modules, Pcap4J always returns a [UnknownPacket](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/UnknownPacket.java) object when it captures a packet.
Learn more about Packet Factory [here](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md).

The other modules' artifacts are not needed when you run a Pcap4J application.
