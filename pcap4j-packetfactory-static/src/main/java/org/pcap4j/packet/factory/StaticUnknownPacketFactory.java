/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class StaticUnknownPacketFactory implements PacketFactory<Packet, NamedNumber<?, ?>> {

  private static final StaticUnknownPacketFactory INSTANCE = new StaticUnknownPacketFactory();

  private StaticUnknownPacketFactory() {}

  /**
   * @return the singleton instance of StaticUnknownPacketFactory.
   */
  public static StaticUnknownPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, NamedNumber<?, ?>... numbers) {
    return UnknownPacket.newPacket(rawData, offset, length);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
