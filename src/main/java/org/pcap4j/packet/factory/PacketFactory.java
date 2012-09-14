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
 */
public interface PacketFactory {

  // /* must implement. called by PacketFactories. */
  // public static PacketFactory getInstance();

  /**
   *
   * @param rawData
   * @param number
   * @return
   */
  public Packet newPacket(byte[] rawData, NamedNumber<?> number);

  /**
   *
   * @param rawData
   * @return
   */
  public Packet newPacket(byte[] rawData);

}
