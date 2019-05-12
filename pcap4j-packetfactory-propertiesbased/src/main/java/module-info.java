module org.pcap4j.packetfactory.propertiesbased {
  requires org.pcap4j.core;
  requires java.sql;

  // opens this package so that PacketFactoryPropertiesLoader can load packet-factory.properties
  opens org.pcap4j.packet.factory.propertiesbased;

  provides org.pcap4j.packet.factory.PacketFactoryBinderProvider with
      org.pcap4j.packet.factory.propertiesbased.services.PropertiesBasedPacketFactoryBinderProvider;
}
