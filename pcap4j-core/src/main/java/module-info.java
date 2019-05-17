module org.pcap4j.core {
  exports org.pcap4j.core;
  exports org.pcap4j.packet;
  exports org.pcap4j.packet.factory;
  exports org.pcap4j.packet.namednumber;
  exports org.pcap4j.packet.constant;
  exports org.pcap4j.util;

  opens org.pcap4j.packet;
  opens org.pcap4j.packet.namednumber;

  requires com.sun.jna;
  requires slf4j.api;

  uses org.pcap4j.packet.factory.PacketFactoryBinderProvider;
}
