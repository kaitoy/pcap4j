/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
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

  private IcmpV4Helper() { throw new AssertionError(); }

  /**
   *
   * @param packet IPv4 Packet
   * @return a new Packet object.
   */
  public static Packet makePacketForInvokingPacketField(Packet packet) {
    return IcmpV6Helper.makePacketForInvokingPacketField(packet, 8);
  }

}
