/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public interface RawPacketListener {

  /** @param packet packet */
  public void gotPacket(byte[] packet);
}
