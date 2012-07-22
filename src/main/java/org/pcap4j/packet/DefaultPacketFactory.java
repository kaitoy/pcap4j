/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PacketFactory;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class DefaultPacketFactory implements PacketFactory {

  private static final DefaultPacketFactory INSTANCE
    = new DefaultPacketFactory();

  private DefaultPacketFactory() {};

  /**
   *
   * @return
   */
  public static DefaultPacketFactory getInstance() { return INSTANCE; }

  public Packet newPacket(byte[] rawData, NamedNumber<?> number) {
    if (rawData == null || number == null) {
      throw new NullPointerException(
                  "rawData: " + rawData + " number: " + number
                );
    }

    if (number instanceof DataLinkType) {
      if (number.equals(DataLinkType.EN10MB)) {
        return EthernetPacket.newPacket(rawData);
      }
    }
    else if (number instanceof EtherType) {
      if (number.equals(EtherType.IP_V4)) {
        return IpV4Packet.newPacket(rawData);
      }
      else if (number.equals(EtherType.IP_V6)) {
        return IpV6Packet.newPacket(rawData);
      }
      else if (number.equals(EtherType.ARP)) {
        return ArpPacket.newPacket(rawData);
      }
      else if (number.equals(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)) {
        return Dot1qVlanTaggedPacket.newPacket(rawData);
      }
    }
    else if (number instanceof IpNumber) {
      if (number.equals(IpNumber.UDP)) {
        return UdpPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.ICMP_V4)) {
        return IcmpV4Packet.newPacket(rawData);
      }
      else if (number.equals(IpNumber.HOPOPT)) {
        return IpV6ExtHopByHopOptionsPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IP_V6_FRAG)) {
        return IpV6ExtFragmentPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IP_V6_OPTS)) {
        return IpV6ExtDestinationOptionsPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IP_V6_ROUTE)) {
        return IpV6ExtRoutingPacket.newPacket(rawData);
      }
      else if (number.equals(IpNumber.IP_V6_NONXT)) {
        return AnonymousPacket.newPacket(rawData);
      }
    }
//    else if (number instanceof UdpPort) {
//
//    }
    return AnonymousPacket.newPacket(rawData);
  }

}
