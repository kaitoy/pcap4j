/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 * @param <T>
 */
public interface PacketFactory<T extends NamedNumber<?>> {

  // /* must implement. called by PacketFactories. */
  // public static PacketFactory getInstance();

  /**
   *
   * @param rawData
   * @param number
   * @return a new Packet object.
   */
  public Packet newPacket(byte[] rawData, T number);

}
