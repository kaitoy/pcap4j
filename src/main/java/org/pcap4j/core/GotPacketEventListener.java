/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.packet.Packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public interface GotPacketEventListener {

  /**
   *
   * @param packet
   */
  public void gotPacket(Packet packet);

}
