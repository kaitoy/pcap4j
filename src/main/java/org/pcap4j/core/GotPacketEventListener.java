/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.packet.Packet;

public interface GotPacketEventListener {
  public void gotPacket(Packet packet);
}
