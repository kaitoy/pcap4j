/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.GtpV1ExtPduSessionContainerPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.8.3
 */
public final class StaticGtpV1ExtensionPacketFactory
    implements PacketFactory<Packet, GtpV1ExtensionHeaderType> {

  private static final StaticGtpV1ExtensionPacketFactory INSTANCE =
      new StaticGtpV1ExtensionPacketFactory();

  private StaticGtpV1ExtensionPacketFactory() {}

  /** @return the singleton instance of StaticGtpV1ExtensionPacketFactory. */
  public static StaticGtpV1ExtensionPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, GtpV1ExtensionHeaderType...)}
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
   * This method is a variant of {@link #newInstance(byte[], int, int, GtpV1ExtensionHeaderType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(
      byte[] rawData, int offset, int length, GtpV1ExtensionHeaderType number) {
    try {
      byte val = number.value();
      switch (val & 0xff) {
        case 0x85:
          return GtpV1ExtPduSessionContainerPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, GtpV1ExtensionHeaderType...)}
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
      byte[] rawData,
      int offset,
      int length,
      GtpV1ExtensionHeaderType number1,
      GtpV1ExtensionHeaderType number2) {
    try {
      byte val = number1.value();
      switch (val & 0xff) {
        case 0x85:
          return GtpV1ExtPduSessionContainerPacket.newPacket(rawData, offset, length);
      }

      val = number2.value();
      switch (val & 0xff) {
        case 0x85:
          return GtpV1ExtPduSessionContainerPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(
      byte[] rawData, int offset, int length, GtpV1ExtensionHeaderType... numbers) {
    try {
      for (GtpV1ExtensionHeaderType num : numbers) {
        byte val = num.value();
        switch (val & 0xff) {
          case 0x85:
            return GtpV1ExtPduSessionContainerPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
