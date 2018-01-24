/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, NotApplicable...)}
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
   * This method is a variant of {@link #newInstance(byte[], int, int, NotApplicable...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, NotApplicable number) {
    switch (Byte.toUnsignedInt(number.value())) {
      case 0:
        return UnknownPacket.newPacket(rawData, offset, length);
      case 1:
        return FragmentedPacket.newPacket(rawData, offset, length);
      case 2:
        return CompressedPacket.newPacket(rawData, offset, length);
      case 3:
        return EncryptedPacket.newPacket(rawData, offset, length);
    }
    return UnknownPacket.newPacket(rawData, offset, length);
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, NotApplicable...)}
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
    byte[] rawData, int offset, int length, NotApplicable number1, NotApplicable number2
  ) {
    switch (Byte.toUnsignedInt(number1.value())) {
      case 0:
        return UnknownPacket.newPacket(rawData, offset, length);
      case 1:
        return FragmentedPacket.newPacket(rawData, offset, length);
      case 2:
        return CompressedPacket.newPacket(rawData, offset, length);
      case 3:
        return EncryptedPacket.newPacket(rawData, offset, length);
    }

    switch (Byte.toUnsignedInt(number2.value())) {
      case 0:
        return UnknownPacket.newPacket(rawData, offset, length);
      case 1:
        return FragmentedPacket.newPacket(rawData, offset, length);
      case 2:
        return CompressedPacket.newPacket(rawData, offset, length);
      case 3:
        return EncryptedPacket.newPacket(rawData, offset, length);
    }
    return UnknownPacket.newPacket(rawData, offset, length);
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, NotApplicable... numbers) {
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
