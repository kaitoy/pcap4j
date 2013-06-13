/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket;
import org.pcap4j.packet.IpV6ExtFragmentPacket;
import org.pcap4j.packet.IpV6ExtHopByHopOptionsPacket;
import org.pcap4j.packet.IpV6ExtRoutingPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIpNumberPacketFactory
extends AbstractStaticPacketFactory<IpNumber> {

  private static final StaticIpNumberPacketFactory INSTANCE
    = new StaticIpNumberPacketFactory();

  private StaticIpNumberPacketFactory() {
    instantiaters.put(
      IpNumber.UDP, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return UdpPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.ICMPV4, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4CommonPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.ICMPV6, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV6CommonPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.TCP, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return TcpPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.IPV6_HOPOPT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IpV6ExtHopByHopOptionsPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.IPV6_FRAG, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IpV6ExtFragmentPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.IPV6_DST_OPTS, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IpV6ExtDestinationOptionsPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.IPV6_ROUTE, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IpV6ExtRoutingPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IpNumber.IPV6_NONXT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return UnknownPacket.newPacket(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIpNumberPacketFactory.
   */
  public static StaticIpNumberPacketFactory getInstance() {
    return INSTANCE;
  }

}
