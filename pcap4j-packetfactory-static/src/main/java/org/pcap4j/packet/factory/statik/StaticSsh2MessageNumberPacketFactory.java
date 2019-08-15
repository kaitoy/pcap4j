/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Ssh2KexInitPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class StaticSsh2MessageNumberPacketFactory
    implements PacketFactory<Packet, Ssh2MessageNumber> {

  private static final StaticSsh2MessageNumberPacketFactory INSTANCE =
      new StaticSsh2MessageNumberPacketFactory();

  private StaticSsh2MessageNumberPacketFactory() {}

  /** @return the singleton instance of StaticSsh2MessageNumberPacketFactory. */
  public static StaticSsh2MessageNumberPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, Ssh2MessageNumber...)} and
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
   * This method is a variant of {@link #newInstance(byte[], int, int, Ssh2MessageNumber...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, Ssh2MessageNumber number) {
    try {
      switch (number.value() & 0xff) {
        case 20:
          return Ssh2KexInitPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, Ssh2MessageNumber...)} and
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
      byte[] rawData,
      int offset,
      int length,
      Ssh2MessageNumber number1,
      Ssh2MessageNumber number2) {
    try {
      switch (number1.value() & 0xff) {
        case 20:
          return Ssh2KexInitPacket.newPacket(rawData, offset, length);
      }

      switch (number2.value() & 0xff) {
        case 20:
          return Ssh2KexInitPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, Ssh2MessageNumber... numbers) {
    try {
      for (Ssh2MessageNumber num : numbers) {
        switch (num.value() & 0xff) {
          case 20:
            return Ssh2KexInitPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
