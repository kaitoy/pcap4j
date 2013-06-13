/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticUdpPortPacketFactory
implements PacketFactory<UdpPort> {

  private static final StaticUdpPortPacketFactory INSTANCE
    = new StaticUdpPortPacketFactory();

  private StaticUdpPortPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticUdpPortPacketFactory.
   */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, UdpPort port) {
    if (rawData == null || port == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" port: ")
        .append(port);
      throw new NullPointerException(sb.toString());
    }

//    try {
//      if (port.equals(UdpPort.SNMP)) {
//        UnknownPacket.newPacket(rawData);
//      }
//    } catch (IllegalRawDataException e) {
//      return IllegalPacket.newPacket(rawData);
//    }

    return UnknownPacket.newPacket(rawData);
  }

}
