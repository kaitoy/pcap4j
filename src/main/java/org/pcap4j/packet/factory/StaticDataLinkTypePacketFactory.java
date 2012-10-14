/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticDataLinkTypePacketFactory
implements PacketFactory<DataLinkType> {

  private static final StaticDataLinkTypePacketFactory INSTANCE
    = new StaticDataLinkTypePacketFactory();

  private StaticDataLinkTypePacketFactory() {};

  /**
   *
   * @return
   */
  public static StaticDataLinkTypePacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, DataLinkType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number.equals(DataLinkType.EN10MB)) {
        return EthernetPacket.newPacket(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

}
