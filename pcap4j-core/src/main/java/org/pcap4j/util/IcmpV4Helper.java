/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import org.pcap4j.packet.Packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4Helper {

  private IcmpV4Helper() {
    throw new AssertionError();
  }

  /**
   * @param packet an IPv4 Packet
   * @return a new Packet object.
   */
  public static Packet makePacketForInvokingPacketField(Packet packet) {
    if (packet == null || packet.getHeader() == null || packet.getPayload() == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("packet: ")
          .append(packet)
          .append(" packet.getHeader(): ")
          .append(packet.getHeader())
          .append(" packet.getPayload(): ")
          .append(packet.getPayload());
      throw new NullPointerException(sb.toString());
    }

    return IcmpV6Helper.makePacketForInvokingPacketField(packet, 8 + packet.getHeader().length());
  }
}
