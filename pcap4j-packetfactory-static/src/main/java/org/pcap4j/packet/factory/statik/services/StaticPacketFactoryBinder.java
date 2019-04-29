/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik.services;

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
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.8.0
 */
final class StaticPacketFactoryBinder implements PacketFactoryBinder {

  private static final PacketFactoryBinder INSTANCE = new StaticPacketFactoryBinder();

  private StaticPacketFactoryBinder() {}

  public static PacketFactoryBinder getInstance() {
    return INSTANCE;
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
      Class<T> targetClass, Class<N> numberClass) {
    switch (targetClass.getName()) {
      case "org.pcap4j.packet.Packet":
        switch (numberClass.getName()) {
          case "org.pcap4j.packet.namednumber.DataLinkType":
            return (PacketFactory<T, N>) StaticDataLinkTypePacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.EtherType":
            return (PacketFactory<T, N>) StaticEtherTypePacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.LlcNumber":
            return (PacketFactory<T, N>) StaticLlcNumberPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.IcmpV4Type":
            return (PacketFactory<T, N>) StaticIcmpV4TypePacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.IcmpV6Type":
            return (PacketFactory<T, N>) StaticIcmpV6TypePacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.IpNumber":
            return (PacketFactory<T, N>) StaticIpNumberPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.TcpPort":
            return (PacketFactory<T, N>) StaticTcpPortPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.UdpPort":
            return (PacketFactory<T, N>) StaticUdpPortPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.SctpPort":
            return (PacketFactory<T, N>) StaticSctpPortPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.NotApplicable":
            return (PacketFactory<T, N>) StaticNotApplicablePacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.PppDllProtocol":
            return (PacketFactory<T, N>) StaticPppDllProtocolPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.ProtocolFamily":
            return (PacketFactory<T, N>) StaticProtocolFamilyPacketFactory.getInstance();
          case "org.pcap4j.packet.namednumber.Dot11FrameType":
            return (PacketFactory<T, N>) StaticDot11FrameTypePacketFactory.getInstance();
          default:
            return (PacketFactory<T, N>) StaticUnknownPacketFactory.getInstance();
        }
      case "org.pcap4j.packet.IpV4Packet$IpV4Option":
        return (PacketFactory<T, N>) StaticIpV4OptionFactory.getInstance();
      case "org.pcap4j.packet.IpV4InternetTimestampOption":
        return (PacketFactory<T, N>) StaticIpV4InternetTimestampOptionDataFactory.getInstance();
      case "org.pcap4j.packet.TcpPacket$TcpOption":
        return (PacketFactory<T, N>) StaticTcpOptionFactory.getInstance();
      case "org.pcap4j.packet.IpV6ExtOptionsPacket$IpV6Option":
        return (PacketFactory<T, N>) StaticIpV6OptionFactory.getInstance();
      case "org.pcap4j.packet.IpV6ExtRoutingPacket$IpV6RoutingData":
        return (PacketFactory<T, N>) StaticIpV6RoutingDataFactory.getInstance();
      case "org.pcap4j.packet.IcmpV6CommonPacket$IpV6NeighborDiscoveryOption":
        return (PacketFactory<T, N>) StaticIpV6NeighborDiscoveryOptionFactory.getInstance();
      case "org.pcap4j.packet.IpV4Packet$IpV4Tos":
        return (PacketFactory<T, N>) StaticIpV4TosFactory.getInstance();
      case "org.pcap4j.packet.IpV6Packet$IpV6TrafficClass":
        return (PacketFactory<T, N>) StaticIpV6TrafficClassFactory.getInstance();
      case "org.pcap4j.packet.IpV6Packet$IpV6FlowLabel":
        return (PacketFactory<T, N>) StaticIpV6FlowLabelFactory.getInstance();
      case "org.pcap4j.packet.RadiotapPacket$RadiotapData":
        return (PacketFactory<T, N>) StaticRadiotapDataFieldFactory.getInstance();
      case "org.pcap4j.packet.SctpPacket$SctpChunk":
        return (PacketFactory<T, N>) StaticSctpChunkFactory.getInstance();
      case "org.pcap4j.packet.DnsResourceRecord$DnsRData":
        return (PacketFactory<T, N>) StaticDnsRDataFactory.getInstance();
      default:
        throw new IllegalStateException("Unsupported target: " + targetClass);
    }
  }
}
