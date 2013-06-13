/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticEtherTypePacketFactory
implements PacketFactory<EtherType> {

  private static final StaticEtherTypePacketFactory INSTANCE
    = new StaticEtherTypePacketFactory();

  private StaticEtherTypePacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticEtherTypePacketFactory.
   */
  public static StaticEtherTypePacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, EtherType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number.equals(EtherType.IPV4)) {
        return IpV4Packet.newPacket(rawData);
      }
      else if (number.equals(EtherType.IPV6)) {
        return IpV6Packet.newPacket(rawData);
      }
      else if (number.equals(EtherType.ARP)) {
        return ArpPacket.newPacket(rawData);
      }
      else if (number.equals(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)) {
        return Dot1qVlanTagPacket.newPacket(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

}
