/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, LlcNumber...)}
   * and exists only for performance reason.
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
   * This method is a variant of {@link #newInstance(byte[], int, int, LlcNumber...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, LlcNumber number) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 152:
          return ArpPacket.newPacket(rawData, offset, length);
        case 170:
          return SnapPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, LlcNumber...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(
    byte[] rawData, int offset, int length, LlcNumber number1, LlcNumber number2
  ) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 152:
          return ArpPacket.newPacket(rawData, offset, length);
        case 170:
          return SnapPacket.newPacket(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 152:
          return ArpPacket.newPacket(rawData, offset, length);
        case 170:
          return SnapPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, LlcNumber... numbers) {
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
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

}
