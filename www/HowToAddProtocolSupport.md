How to add a protocol support
=============================

1. Write your packet class<br>
  Firstly, you need to write packet classes which represent packets used in the protocol you want to add.
  A packet class must implement [org.pcap4j.packet.Packet interface](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/Packet.java).
  Actually, in most cases, you should extend [org.pcap4j.packet.AbstractPacket class](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-core/src/main/java/org/pcap4j/packet/AbstractPacket.java),
  which is an abstract class implementing many of Packet's methods so you can save time.

  And, it's recommended to write a static factory method in the packet class such as below:

  ```java
  public static YourPacket newPacket(byte[] rawData, int offset, int length) {
    return new YourPacket(rawData);
  }
  ```

  With this static factory method, you can use [the Properties-Based Packet Factory](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md#properties-based-packet-factory) for the packet class.

  To write a packet class, you need to write also a header class and a builder class.
  The header class must implements org.pcap4j.packet.Packet.Header or extends org.pcap4j.packet.AbstractPacket.AbstractHeader.
  The builder class must implements org.pcap4j.packet.Packet.Builder or extends org.pcap4j.packet.AbstractPacket.AbstractBuilder.

  The responsibilities of a packet class are the following:
  * Building its header object in the constructor (if it has a header).
  * Building its payload object in the constructor (if it has a payload).
  * Building its builder object in the getBuilder method.

2. Configure Packet Factory<br>
  Secondly, you need to configure Packet Factory so it properly instantiates packet objects from your packet classes.
  Assuming your packet class represents a protocol over TCP and the protocol uses port 1234,
  there are three ways to configure Packet Factory.

  2.1. Using [the Properties-Based Packet Factory](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md#properties-based-packet-factory)<br>
  Add the following line to `jar:file:/path/to/pcap4j-packetfactory-propertiesbased.jar!/org/pcap4j/packet/factory/packet-factory.properties`:

  ```org.pcap4j.packet.Packet.classFor.org.pcap4j.packet.namednumber.TcpPort.1234 = org.pcap4j.packet.YourPacket```

  Or, if you don't want to modify packet-factory.properties in the jar, add the following system property before starting the first packet capture:

  ```org.pcap4j.packet.Packet.classFor.org.pcap4j.packet.namednumber.TcpPort.1234 = org.pcap4j.packet.YourPacket```

  Note system properties always take precedence over properties in packet-factory.properties.

  If you want to use your own properties file, set the system property `org.pcap4j.packet.factory.properties` to the path to your properties file.
  This makes the Properties-Based Packet Factory load the properties file using `java.lang.ClassLoader#getResourceAsStream` method and
  use it instead of packet-factory.properties in Properties-Based Packet Factory module.

  2.2. Using [Static Packet Factory](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md#static-packet-factory)<br>
  Modify the source [StaticTcpPortPacketFactory.java](https://github.com/kaitoy/pcap4j/blob/v1/pcap4j-packetfactory-static/src/main/java/org/pcap4j/packet/factory/statik/StaticTcpPortPacketFactory.java)
  and add the following to its constructor:

  ```java
  instantiaters.put(
    TcpPort.getInstance((short)1234),
    new PacketInstantiater(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      return YourPacket.newPacket(rawData, offset, length);
    }
  );
  ```

  Then, build the Static Packet Factory and use the new module.

  2.3. Create your own Packet Factory module<br>
  To be written.
