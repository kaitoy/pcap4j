How to add a protocol support
=============================

1. Write your packet class<br>
  A packet class must implement org.pcap4j.packet.Packet interface.
  Actually, in most cases, you should extend org.pcap4j.packet.AbstractPacket class,
  which is an abstract class implementing many of Packet's methods, so you can save your time.

  And It's recommended to write a static factory method in the packet class such as below:

        public static YourPacket newPacket(byte[] rawData) {
          return new YourPacket(rawData);
        }

  With this static factory method, you can use [PropertiesBasedPacketFactory](/www/Packet.md#properties_based_packet_factory) for the packet class.

  To write a packet class, you need to write also a header class and builder class.
  The header class must implements org.pcap4j.packet.Packet.Header or extends org.pcap4j.packet.AbstractPacket.AbstractHeader.
  The builder class must implements org.pcap4j.packet.Packet.Builder or extends org.pcap4j.packet.AbstractPacket.AbstractBuilder.

  The responsibilities of a packet class are the following:
  * Building its header object in the constructor.
  * Building its payload object in the constructor.
  * Building its builder object in the getBuilder method.

2. Configure packet factory<br>
  There are some ways to configure packet factory for your packet class. You'll see some examples using [PropertiesBasedPacketFactory](/www/Packet.md#properties_based_packet_factory) here.
  If your packet class represents a protocol over TCP and the port number is 1234,
  modify `jar:file:/path/to/pcap4j-packetfactory-propertiesbased.jar!/org/pcap4j/packet/factory/packet-factory.properties` as below:

        (snip)
        
        ## TCP Port (http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml)
        ## Add this line to let PropertiesBasedPacketFactory instantiate YourPacket class by the port 1234.
        org.pcap4j.packet.Packet.classFor.org.pcap4j.packet.namednumber.TcpPort.1234 = org.pcap4j.packet.YourPacket
        #org.pcap4j.packet.Packet.classFor.org.pcap4j.packet.namednumber.TcpPort.161 = org.pcap4j.packet.SnmpPacket # not implemented
        
        (snip)

  If you don't want to modify packet-factory.properties in the jar, add the following system properties before starting a packet capture:

        org.pcap4j.packet.Packet.classFor.org.pcap4j.packet.namednumber.TcpPort.1234 = org.pcap4j.packet.YourPacket

  Note system properties always take precedence over properties in packet-factory.properties.

  There is another way to do the same thing. If a system property org.pcap4j.packet.factory.properties is set,
  Pcap4J will load the file the property specifies using java.lang.ClassLoader#getResourceAsStream method and
  use it instead of packet-factory.properties in pcap4j-packetfactory-propertiesbased.jar.
