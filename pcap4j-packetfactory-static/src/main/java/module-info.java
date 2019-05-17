module org.pcap4j.packetfactory.statik {
  requires org.pcap4j.core;

  provides org.pcap4j.packet.factory.PacketFactoryBinderProvider with
      org.pcap4j.packet.factory.statik.services.StaticPacketFactoryBinderProvider;
}
