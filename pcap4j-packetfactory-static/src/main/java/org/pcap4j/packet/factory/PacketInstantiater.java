/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;

abstract class PacketInstantiater {

  public abstract Packet newInstance(byte [] rawData);

}
