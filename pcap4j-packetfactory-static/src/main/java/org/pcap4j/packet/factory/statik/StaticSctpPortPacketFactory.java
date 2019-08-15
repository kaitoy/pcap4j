/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.SctpPort;

/**
 * @author Jeff Myers
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class StaticSctpPortPacketFactory implements PacketFactory<Packet, SctpPort> {

  private static final StaticSctpPortPacketFactory INSTANCE = new StaticSctpPortPacketFactory();

  private StaticSctpPortPacketFactory() {}

  /** @return the singleton instance of StaticSctpPortPacketFactory. */
  public static StaticSctpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpPort...)} and exists only
   * for performance reason.
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
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpPort...)} and exists only
   * for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, SctpPort number) {
    return UnknownPacket.newPacket(rawData, offset, length);
    //    try {
    //      switch (number.value() & 0xffff) {
    //        case 80:
    //          return HttpPacket.newPacket(rawData, offset, length);
    //      }
    //      return UnknownPacket.newPacket(rawData, offset, length);
    //    } catch (IllegalRawDataException e) {
    //      return IllegalPacket.newPacket(rawData, offset, length, e);
    //    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpPort...)} and exists only
   * for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(
      byte[] rawData, int offset, int length, SctpPort number1, SctpPort number2) {
    return UnknownPacket.newPacket(rawData, offset, length);
    //    try {
    //      switch (number1.value() & 0xffff) {
    //        case 80:
    //          return HttpPacket.newPacket(rawData, offset, length);
    //      }
    //
    //      switch (number2.value() & 0xffff) {
    //        case 80:
    //          return HttpPacket.newPacket(rawData, offset, length);
    //      }
    //      return UnknownPacket.newPacket(rawData, offset, length);
    //    } catch (IllegalRawDataException e) {
    //      return IllegalPacket.newPacket(rawData, offset, length, e);
    //    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, SctpPort... numbers) {
    return UnknownPacket.newPacket(rawData, offset, length);
    //    try {
    //      for (SctpPort num: numbers) {
    //        switch (num.value() & 0xffff) {
    //          case 80:
    //            return HttpPacket.newPacket(rawData, offset, length);
    //        }
    //      }
    //      return UnknownPacket.newPacket(rawData, offset, length);
    //    } catch (IllegalRawDataException e) {
    //      return IllegalPacket.newPacket(rawData, offset, length, e);
    //    }
  }
}
