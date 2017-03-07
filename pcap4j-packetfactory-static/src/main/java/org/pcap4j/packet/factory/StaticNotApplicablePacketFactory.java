/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.CompressedPacket;
import org.pcap4j.packet.EncryptedPacket;
import org.pcap4j.packet.FragmentedPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.NotApplicable;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class StaticNotApplicablePacketFactory
implements PacketFactory<Packet, NotApplicable> {

  private static final StaticNotApplicablePacketFactory INSTANCE
    = new StaticNotApplicablePacketFactory();

  private StaticNotApplicablePacketFactory() {}

  /**
   * @return the singleton instance of StaticNotApplicablePacketFactory.
   */
  public static StaticNotApplicablePacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, NotApplicable... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    for (NotApplicable num: numbers) {
      switch (Byte.toUnsignedInt(num.value())) {
        case 0:
          return UnknownPacket.newPacket(rawData, offset, length);
        case 1:
          return FragmentedPacket.newPacket(rawData, offset, length);
        case 2:
          return CompressedPacket.newPacket(rawData, offset, length);
        case 3:
          return EncryptedPacket.newPacket(rawData, offset, length);
      }
    }
    return UnknownPacket.newPacket(rawData, offset, length);
  }

}
