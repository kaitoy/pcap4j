/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SnapPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.LlcNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class StaticLlcNumberPacketFactory implements PacketFactory<Packet, LlcNumber> {

  private static final StaticLlcNumberPacketFactory INSTANCE
    = new StaticLlcNumberPacketFactory();

  private StaticLlcNumberPacketFactory() {}

  /**
   * @return the singleton instance of StaticLlcNumberPacketFactory.
   */
  public static StaticLlcNumberPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, LlcNumber... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (LlcNumber num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 152:
            return ArpPacket.newPacket(rawData, offset, length);
          case 170:
            return SnapPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
