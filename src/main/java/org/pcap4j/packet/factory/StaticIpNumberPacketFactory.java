/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
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
implements PacketFactory<IpNumber> {

  private static final StaticIpNumberPacketFactory INSTANCE
    = new StaticIpNumberPacketFactory();

  private StaticIpNumberPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticIpNumberPacketFactory.
   */
  public static StaticIpNumberPacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, IpNumber number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number.equals(IpNumber.UDP)) {
        return UdpPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.ICMPV4)) {
        return IcmpV4CommonPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.ICMPV6)) {
        return IcmpV6CommonPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.TCP)) {
        return TcpPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IPV6_HOPOPT)) {
        return IpV6ExtHopByHopOptionsPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IPV6_FRAG)) {
        return IpV6ExtFragmentPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IPV6_DST_OPTS)) {
        return IpV6ExtDestinationOptionsPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IPV6_ROUTE)) {
        return IpV6ExtRoutingPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IPV6_NONXT)) {
        return UnknownPacket.newPacket(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

}
