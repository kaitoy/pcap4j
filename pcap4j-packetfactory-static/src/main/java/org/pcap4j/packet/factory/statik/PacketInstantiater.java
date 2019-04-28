/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

interface PacketInstantiater {

  public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException;

  public Class<? extends Packet> getTargetClass();
}
