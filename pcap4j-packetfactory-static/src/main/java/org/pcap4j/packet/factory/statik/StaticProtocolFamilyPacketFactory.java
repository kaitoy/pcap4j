/*_##########################################################################
  _##
  _##  Copyright (C) 2015-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.ProtocolFamily;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.5.0
 */
public final class StaticProtocolFamilyPacketFactory
    implements PacketFactory<Packet, ProtocolFamily> {

  private static final StaticProtocolFamilyPacketFactory INSTANCE =
      new StaticProtocolFamilyPacketFactory();

  private StaticProtocolFamilyPacketFactory() {}

  /** @return the singleton instance of StaticProtocolFamilyPacketFactory. */
  public static StaticProtocolFamilyPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, ProtocolFamily...)} and
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
   * This method is a variant of {@link #newInstance(byte[], int, int, ProtocolFamily...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, ProtocolFamily number) {
    try {
      if (number == ProtocolFamily.PF_INET) {
        return IpV4Packet.newPacket(rawData, offset, length);
      } else if (number == ProtocolFamily.PF_INET6) {
        return IpV6Packet.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, ProtocolFamily...)} and
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
      byte[] rawData, int offset, int length, ProtocolFamily number1, ProtocolFamily number2) {
    try {
      if (number1 == ProtocolFamily.PF_INET) {
        return IpV4Packet.newPacket(rawData, offset, length);
      } else if (number1 == ProtocolFamily.PF_INET6) {
        return IpV6Packet.newPacket(rawData, offset, length);
      }

      if (number2 == ProtocolFamily.PF_INET) {
        return IpV4Packet.newPacket(rawData, offset, length);
      } else if (number2 == ProtocolFamily.PF_INET6) {
        return IpV6Packet.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, ProtocolFamily... numbers) {
    try {
      for (ProtocolFamily num : numbers) {
        if (num == ProtocolFamily.PF_INET) {
          return IpV4Packet.newPacket(rawData, offset, length);
        } else if (num == ProtocolFamily.PF_INET6) {
          return IpV6Packet.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
