/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticTcpPortPacketFactory
implements PacketFactory<TcpPort> {

  private static final StaticTcpPortPacketFactory INSTANCE
    = new StaticTcpPortPacketFactory();

  private StaticTcpPortPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticTcpPortPacketFactory.
   */
  public static StaticTcpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, TcpPort port) {
    if (rawData == null || port == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" port: ")
        .append(port);
      throw new NullPointerException(sb.toString());
    }

//    try {
//      if (port.equals(TcpPort.SNMP)) {
//        UnknownPacket.newPacket(rawData);
//      }
//    } catch (IllegalRawDataException e) {
//      return IllegalPacket.newPacket(rawData);
//    }

    return UnknownPacket.newPacket(rawData);
  }

}
