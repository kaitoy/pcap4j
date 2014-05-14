/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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
implements PacketFactory<Packet, NamedNumber<?, ?>> {

  private static final StaticUnknownPacketFactory INSTANCE
    = new StaticUnknownPacketFactory();

  private StaticUnknownPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticUnknownPacketFactory.
   */
  public static StaticUnknownPacketFactory getInstance() { return INSTANCE; }

  public Packet newInstance(byte[] rawData, NamedNumber<?, ?> number) {
    return newInstance(rawData);
  }

  public Packet newInstance(byte[] rawData) {
    return UnknownPacket.newPacket(rawData);
  }

}
