/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  private static final StaticDot11FrameTypePacketFactory INSTANCE =
      new StaticDot11FrameTypePacketFactory();

  private StaticDot11FrameTypePacketFactory() {}

  /** @return the singleton instance of StaticDot11FrameTypePacketFactory. */
  public static StaticDot11FrameTypePacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, Dot11FrameType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length) {
    return UnknownPacket.newPacket(rawData, offset, length);
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, Dot11FrameType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, Dot11FrameType number) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 4:
          return Dot11ProbeRequestPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, Dot11FrameType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(
      byte[] rawData, int offset, int length, Dot11FrameType number1, Dot11FrameType number2) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 4:
          return Dot11ProbeRequestPacket.newPacket(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 4:
          return Dot11ProbeRequestPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, Dot11FrameType... numbers) {
    try {
      for (Dot11FrameType num : numbers) {
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
}
