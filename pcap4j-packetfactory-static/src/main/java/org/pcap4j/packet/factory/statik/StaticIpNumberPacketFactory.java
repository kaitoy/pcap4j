/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket;
import org.pcap4j.packet.IpV6ExtFragmentPacket;
import org.pcap4j.packet.IpV6ExtHopByHopOptionsPacket;
import org.pcap4j.packet.IpV6ExtRoutingPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SctpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIpNumberPacketFactory extends AbstractStaticPacketFactory<IpNumber> {

  private static final StaticIpNumberPacketFactory INSTANCE = new StaticIpNumberPacketFactory();

  private StaticIpNumberPacketFactory() {
    instantiaters.put(
        IpNumber.UDP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return UdpPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<UdpPacket> getTargetClass() {
            return UdpPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.ICMPV4,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4CommonPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4CommonPacket> getTargetClass() {
            return IcmpV4CommonPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.ICMPV6,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6CommonPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6CommonPacket> getTargetClass() {
            return IcmpV6CommonPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.TCP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return TcpPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<TcpPacket> getTargetClass() {
            return TcpPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.IPV6_HOPOPT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6ExtHopByHopOptionsPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6ExtHopByHopOptionsPacket> getTargetClass() {
            return IpV6ExtHopByHopOptionsPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.IPV6_FRAG,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6ExtFragmentPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6ExtFragmentPacket> getTargetClass() {
            return IpV6ExtFragmentPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.IPV6_DST_OPTS,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6ExtDestinationOptionsPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6ExtDestinationOptionsPacket> getTargetClass() {
            return IpV6ExtDestinationOptionsPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.IPV6_ROUTE,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6ExtRoutingPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6ExtRoutingPacket> getTargetClass() {
            return IpV6ExtRoutingPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.IPV6_NONXT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return UnknownPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<UnknownPacket> getTargetClass() {
            return UnknownPacket.class;
          }
        });
    instantiaters.put(
        IpNumber.SCTP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return SctpPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<SctpPacket> getTargetClass() {
            return SctpPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticIpNumberPacketFactory. */
  public static StaticIpNumberPacketFactory getInstance() {
    return INSTANCE;
  }
}
