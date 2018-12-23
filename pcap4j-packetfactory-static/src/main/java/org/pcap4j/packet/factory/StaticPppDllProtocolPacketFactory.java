/*_##########################################################################
  _##
  _##  Copyright (C) 2015-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.PppDllProtocol;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class StaticPppDllProtocolPacketFactory
    implements PacketFactory<Packet, PppDllProtocol> {

  private static final StaticPppDllProtocolPacketFactory INSTANCE =
      new StaticPppDllProtocolPacketFactory();

  private StaticPppDllProtocolPacketFactory() {}

  /** @return the singleton instance of StaticPppDllProtocolPacketFactory. */
  public static StaticPppDllProtocolPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, PppDllProtocol...)} and
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
   * This method is a variant of {@link #newInstance(byte[], int, int, PppDllProtocol...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, PppDllProtocol number) {
    try {
      switch (Short.toUnsignedInt(number.value())) {
        case 0x0021:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0057:
          return IpV6Packet.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, PppDllProtocol...)} and
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
      byte[] rawData, int offset, int length, PppDllProtocol number1, PppDllProtocol number2) {
    try {
      switch (Short.toUnsignedInt(number1.value())) {
        case 0x0021:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0057:
          return IpV6Packet.newPacket(rawData, offset, length);
      }

      switch (Short.toUnsignedInt(number2.value())) {
        case 0x0021:
          return IpV4Packet.newPacket(rawData, offset, length);
        case 0x0057:
          return IpV6Packet.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, PppDllProtocol... numbers) {
    try {
      for (PppDllProtocol num : numbers) {
        switch (Short.toUnsignedInt(num.value())) {
          case 0x0021:
            return IpV4Packet.newPacket(rawData, offset, length);
          case 0x0057:
            return IpV6Packet.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
