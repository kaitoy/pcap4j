/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IpV4InternetTimestampOption;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.NamedNumber;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.pcap4j.packet.namednumber.ProtocolFamily;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.3
 */
final public class StaticPacketFactoryBinder implements PacketFactoryBinder {

  private final Map<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>> packetFactories
    = new HashMap<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>>();
  private final Map<Class<?>, PacketFactory<?, ?>> packetpPieceFactories
    = new HashMap<Class<?>, PacketFactory<?, ?>>();

  public StaticPacketFactoryBinder() {
    packetFactories.put(DataLinkType.class, StaticDataLinkTypePacketFactory.getInstance());
    packetFactories.put(EtherType.class, StaticEtherTypePacketFactory.getInstance());
    packetFactories.put(IcmpV4Type.class, StaticIcmpV4TypePacketFactory.getInstance());
    packetFactories.put(IcmpV6Type.class, StaticIcmpV6TypePacketFactory.getInstance());
    packetFactories.put(IpNumber.class, StaticIpNumberPacketFactory.getInstance());
    packetFactories.put(TcpPort.class, StaticTcpPortPacketFactory.getInstance());
    packetFactories.put(UdpPort.class, StaticUdpPortPacketFactory.getInstance());
    packetFactories.put(NotApplicable.class, StaticNotApplicablePacketFactory.getInstance());
    packetFactories.put(PppDllProtocol.class, StaticPppDllProtocolPacketFactory.getInstance());
    packetFactories.put(ProtocolFamily.class, StaticProtocolFamilyPacketFactory.getInstance());

    packetpPieceFactories.put(
      IpV4Option.class,
      StaticIpV4OptionFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV4InternetTimestampOption.class,
      StaticIpV4InternetTimestampOptionDataFactory.getInstance()
    );
    packetpPieceFactories.put(
      TcpOption.class,
      StaticTcpOptionFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV6Option.class,
      StaticIpV6OptionFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV6RoutingData.class,
      StaticIpV6RoutingDataFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV6NeighborDiscoveryOption.class,
      StaticIpV6NeighborDiscoveryOptionFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV4Tos.class,
      StaticIpV4TosFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV6TrafficClass.class,
      StaticIpV6TrafficClassFactory.getInstance()
    );
    packetpPieceFactories.put(
      IpV6FlowLabel.class,
      StaticIpV6FlowLabelFactory.getInstance()
    );
  }

  @SuppressWarnings("unchecked")
  @Override
  public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    if (Packet.class.isAssignableFrom(targetClass)) {
      return (PacketFactory<T, N>)packetFactories.get(numberClass);
    }
    return (PacketFactory<T, N>)packetpPieceFactories.get(targetClass);
  }

}
