/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.packet.Packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.8
 */
public interface PacketListener {

  /**
   *
   * @param packet
   */
  public void gotPacket(Packet packet);

}
