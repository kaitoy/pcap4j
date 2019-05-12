module org.pcap4j.packetfactory.statik {
  requires org.pcap4j.core;
  requires java.sql;

  provides org.pcap4j.packet.factory.PacketFactoryBinderProvider with
      org.pcap4j.packet.factory.statik.services.StaticPacketFactoryBinderProvider;
}
