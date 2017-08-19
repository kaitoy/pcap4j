/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticEtherTypePacketFactory implements PacketFactory<Packet, EtherType> {

  private static final StaticEtherTypePacketFactory INSTANCE
    = new StaticEtherTypePacketFactory();

  private StaticEtherTypePacketFactory() {}

  /**
   * @return the singleton instance of StaticEtherTypePacketFactory.
   */
  public static StaticEtherTypePacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, EtherType...)}
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
   * This method is a variant of {@link #newInstance(byte[], int, int, EtherType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, EtherType number) {
    try {
      short val = number.value();
      switch (Short.toUnsignedInt(val)) {
        case 0x0800:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0806:
          return ArpPacket.newPacket(rawData, offset, length);
        case 0x8100:
          return Dot1qVlanTagPacket.newPacket(rawData, offset, length);
        case 0x86dd:
          return IpV6Packet.newPacket(rawData, offset, length);
      }
      if ((val & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
        return LlcPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, EtherType...)}
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
    byte[] rawData, int offset, int length, EtherType number1, EtherType number2
  ) {
    try {
      short val = number1.value();
      switch (Short.toUnsignedInt(val)) {
        case 0x0800:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0806:
          return ArpPacket.newPacket(rawData, offset, length);
        case 0x8100:
          return Dot1qVlanTagPacket.newPacket(rawData, offset, length);
        case 0x86dd:
          return IpV6Packet.newPacket(rawData, offset, length);
      }
      if ((val & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
        return LlcPacket.newPacket(rawData, offset, length);
      }

      val = number2.value();
      switch (Short.toUnsignedInt(val)) {
        case 0x0800:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0806:
          return ArpPacket.newPacket(rawData, offset, length);
        case 0x8100:
          return Dot1qVlanTagPacket.newPacket(rawData, offset, length);
        case 0x86dd:
          return IpV6Packet.newPacket(rawData, offset, length);
      }
      if ((val & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
        return LlcPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, EtherType... numbers) {
    try {
      for (EtherType num: numbers) {
        short val = num.value();
        switch (Short.toUnsignedInt(val)) {
          case 0x0800:
            return IpV4Packet.newPacket(rawData, offset, length);
          case 0x0806:
            return ArpPacket.newPacket(rawData, offset, length);
          case 0x8100:
            return Dot1qVlanTagPacket.newPacket(rawData, offset, length);
          case 0x86dd:
            return IpV6Packet.newPacket(rawData, offset, length);
        }
        if ((val & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
          return LlcPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

}
