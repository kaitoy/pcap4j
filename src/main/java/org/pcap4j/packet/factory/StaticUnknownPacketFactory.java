/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticUnknownPacketFactory
implements PacketFactory<NamedNumber<?>> {

  private static final StaticUnknownPacketFactory INSTANCE
    = new StaticUnknownPacketFactory();

  private StaticUnknownPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticUnknownPacketFactory.
   */
  public static StaticUnknownPacketFactory getInstance() { return INSTANCE; }

  public Packet newPacket(byte[] rawData, NamedNumber<?> number) {
    return newPacket(rawData);
  }

  /**
   *
   * @param rawData
   * @return a new Packet object.
   */
  public Packet newPacket(byte[] rawData) {
    return UnknownPacket.newPacket(rawData);
  }

}
