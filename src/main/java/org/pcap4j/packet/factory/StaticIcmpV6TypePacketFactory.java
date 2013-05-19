/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV6EchoReplyPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV6Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticIcmpV6TypePacketFactory
implements PacketFactory<IcmpV6Type> {

  private static final StaticIcmpV6TypePacketFactory INSTANCE
    = new StaticIcmpV6TypePacketFactory();

  private StaticIcmpV6TypePacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticIcmpV6TypePacketFactory.
   */
  public static StaticIcmpV6TypePacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, IcmpV6Type number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number.equals(IcmpV6Type.ECHO_REQUEST)) {
        return IcmpV6EchoRequestPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV6Type.ECHO_REPLY)) {
        return IcmpV6EchoReplyPacket.newPacket(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

}
