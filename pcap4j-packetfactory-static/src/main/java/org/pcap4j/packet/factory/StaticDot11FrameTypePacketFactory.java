/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.Dot11ProbeRequestPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.Dot11FrameType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class StaticDot11FrameTypePacketFactory
implements PacketFactory<Packet, Dot11FrameType> {

  private static final StaticDot11FrameTypePacketFactory INSTANCE
    = new StaticDot11FrameTypePacketFactory();

  private StaticDot11FrameTypePacketFactory() {}

  /**
   * @return the singleton instance of StaticDot11FrameTypePacketFactory.
   */
  public static StaticDot11FrameTypePacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, Dot11FrameType... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (Dot11FrameType num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 4:
            return Dot11ProbeRequestPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
