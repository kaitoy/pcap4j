/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik.services;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IpV4InternetTimestampOption;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.factory.PacketFactoryBinder;
import org.pcap4j.packet.factory.StaticUnknownPacketFactory;
import org.pcap4j.packet.factory.statik.StaticDataLinkTypePacketFactory;
import org.pcap4j.packet.factory.statik.StaticDnsRDataFactory;
import org.pcap4j.packet.factory.statik.StaticDot11FrameTypePacketFactory;
import org.pcap4j.packet.factory.statik.StaticEtherTypePacketFactory;
import org.pcap4j.packet.factory.statik.StaticIcmpV4TypePacketFactory;
import org.pcap4j.packet.factory.statik.StaticIcmpV6TypePacketFactory;
import org.pcap4j.packet.factory.statik.StaticIpNumberPacketFactory;
import org.pcap4j.packet.factory.statik.StaticIpV4InternetTimestampOptionDataFactory;
import org.pcap4j.packet.factory.statik.StaticIpV4OptionFactory;
import org.pcap4j.packet.factory.statik.StaticIpV4TosFactory;
import org.pcap4j.packet.factory.statik.StaticIpV6FlowLabelFactory;
import org.pcap4j.packet.factory.statik.StaticIpV6NeighborDiscoveryOptionFactory;
import org.pcap4j.packet.factory.statik.StaticIpV6OptionFactory;
import org.pcap4j.packet.factory.statik.StaticIpV6RoutingDataFactory;
import org.pcap4j.packet.factory.statik.StaticIpV6TrafficClassFactory;
import org.pcap4j.packet.factory.statik.StaticLlcNumberPacketFactory;
import org.pcap4j.packet.factory.statik.StaticNotApplicablePacketFactory;
import org.pcap4j.packet.factory.statik.StaticPppDllProtocolPacketFactory;
import org.pcap4j.packet.factory.statik.StaticProtocolFamilyPacketFactory;
import org.pcap4j.packet.factory.statik.StaticRadiotapDataFieldFactory;
import org.pcap4j.packet.factory.statik.StaticSctpChunkFactory;
import org.pcap4j.packet.factory.statik.StaticSctpPortPacketFactory;
import org.pcap4j.packet.factory.statik.StaticTcpOptionFactory;
import org.pcap4j.packet.factory.statik.StaticTcpPortPacketFactory;
import org.pcap4j.packet.factory.statik.StaticUdpPortPacketFactory;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.packet.namednumber.NamedNumber;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.pcap4j.packet.namednumber.ProtocolFamily;
import org.pcap4j.packet.namednumber.SctpPort;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.8.0
 */
final class StaticPacketFactoryBinder implements PacketFactoryBinder {

  private static final PacketFactoryBinder INSTANCE = new StaticPacketFactoryBinder();

  private final Map<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>> packetFactories =
      new HashMap<Class<? extends NamedNumber<?, ?>>, PacketFactory<?, ?>>();
  private final Map<Class<?>, PacketFactory<?, ?>> packetpPieceFactories =
      new HashMap<Class<?>, PacketFactory<?, ?>>();

  private StaticPacketFactoryBinder() {
    packetFactories.put(DataLinkType.class, StaticDataLinkTypePacketFactory.getInstance());
    packetFactories.put(EtherType.class, StaticEtherTypePacketFactory.getInstance());
    packetFactories.put(LlcNumber.class, StaticLlcNumberPacketFactory.getInstance());
    packetFactories.put(IcmpV4Type.class, StaticIcmpV4TypePacketFactory.getInstance());
    packetFactories.put(IcmpV6Type.class, StaticIcmpV6TypePacketFactory.getInstance());
    packetFactories.put(IpNumber.class, StaticIpNumberPacketFactory.getInstance());
    packetFactories.put(TcpPort.class, StaticTcpPortPacketFactory.getInstance());
    packetFactories.put(UdpPort.class, StaticUdpPortPacketFactory.getInstance());
    packetFactories.put(SctpPort.class, StaticSctpPortPacketFactory.getInstance());
    packetFactories.put(NotApplicable.class, StaticNotApplicablePacketFactory.getInstance());
    packetFactories.put(PppDllProtocol.class, StaticPppDllProtocolPacketFactory.getInstance());
    packetFactories.put(ProtocolFamily.class, StaticProtocolFamilyPacketFactory.getInstance());
    packetFactories.put(Dot11FrameType.class, StaticDot11FrameTypePacketFactory.getInstance());

    packetpPieceFactories.put(IpV4Option.class, StaticIpV4OptionFactory.getInstance());
    packetpPieceFactories.put(
        IpV4InternetTimestampOption.class,
        StaticIpV4InternetTimestampOptionDataFactory.getInstance());
    packetpPieceFactories.put(TcpOption.class, StaticTcpOptionFactory.getInstance());
    packetpPieceFactories.put(IpV6Option.class, StaticIpV6OptionFactory.getInstance());
    packetpPieceFactories.put(IpV6RoutingData.class, StaticIpV6RoutingDataFactory.getInstance());
    packetpPieceFactories.put(
        IpV6NeighborDiscoveryOption.class, StaticIpV6NeighborDiscoveryOptionFactory.getInstance());
    packetpPieceFactories.put(IpV4Tos.class, StaticIpV4TosFactory.getInstance());
    packetpPieceFactories.put(IpV6TrafficClass.class, StaticIpV6TrafficClassFactory.getInstance());
    packetpPieceFactories.put(IpV6FlowLabel.class, StaticIpV6FlowLabelFactory.getInstance());
    packetpPieceFactories.put(RadiotapData.class, StaticRadiotapDataFieldFactory.getInstance());
    packetpPieceFactories.put(SctpChunk.class, StaticSctpChunkFactory.getInstance());
    packetpPieceFactories.put(DnsRData.class, StaticDnsRDataFactory.getInstance());
  }

  public static PacketFactoryBinder getInstance() {
    return INSTANCE;
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
      Class<T> targetClass, Class<N> numberClass) {
    if (Packet.class.isAssignableFrom(targetClass)) {
      PacketFactory<T, N> factory = (PacketFactory<T, N>) packetFactories.get(numberClass);
      if (factory != null) {
        return factory;
      } else {
        return (PacketFactory<T, N>) StaticUnknownPacketFactory.getInstance();
      }
    }
    return (PacketFactory<T, N>) packetpPieceFactories.get(targetClass);
  }
}
