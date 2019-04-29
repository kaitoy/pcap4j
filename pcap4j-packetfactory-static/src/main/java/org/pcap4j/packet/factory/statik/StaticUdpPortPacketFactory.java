/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.GtpSelector;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticUdpPortPacketFactory implements PacketFactory<Packet, UdpPort> {

  private static final StaticUdpPortPacketFactory INSTANCE = new StaticUdpPortPacketFactory();

  private StaticUdpPortPacketFactory() {}

  /** @return the singleton instance of StaticUdpPortPacketFactory. */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, UdpPort...)} and exists only
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
   * This method is a variant of {@link #newInstance(byte[], int, int, UdpPort...)} and exists only
   * for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, UdpPort number) {
    try {
      switch (Short.toUnsignedInt(number.value())) {
        case 53:
          return DnsPacket.newPacket(rawData, offset, length);
        case 2123:
          return GtpSelector.newPacket(rawData, offset, length);
        case 2152:
          return GtpSelector.newPacket(rawData, offset, length);
        case 3386:
          return GtpSelector.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, UdpPort...)} and exists only
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
      byte[] rawData, int offset, int length, UdpPort number1, UdpPort number2) {
    try {
      switch (Short.toUnsignedInt(number1.value())) {
        case 53:
          return DnsPacket.newPacket(rawData, offset, length);
        case 2123:
          return GtpSelector.newPacket(rawData, offset, length);
        case 2152:
          return GtpSelector.newPacket(rawData, offset, length);
        case 3386:
          return GtpSelector.newPacket(rawData, offset, length);
      }

      switch (Short.toUnsignedInt(number2.value())) {
        case 53:
          return DnsPacket.newPacket(rawData, offset, length);
        case 2123:
          return GtpSelector.newPacket(rawData, offset, length);
        case 2152:
          return GtpSelector.newPacket(rawData, offset, length);
        case 3386:
          return GtpSelector.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, UdpPort... numbers) {
    try {
      for (UdpPort num : numbers) {
        switch (Short.toUnsignedInt(num.value())) {
          case 53:
            return DnsPacket.newPacket(rawData, offset, length);
          case 2123:
            return GtpSelector.newPacket(rawData, offset, length);
          case 2152:
            return GtpSelector.newPacket(rawData, offset, length);
          case 3386:
            return GtpSelector.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
