/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket;
import org.pcap4j.packet.IpV6ExtFragmentPacket;
import org.pcap4j.packet.IpV6ExtHopByHopOptionsPacket;
import org.pcap4j.packet.IpV6ExtRoutingPacket;
import org.pcap4j.packet.IpV6ExtUnknownPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SctpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.UnknownIpV6Extension;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIpNumberPacketFactory implements PacketFactory<Packet, IpNumber> {

  private static final StaticIpNumberPacketFactory INSTANCE = new StaticIpNumberPacketFactory();

  private StaticIpNumberPacketFactory() {}

  /** @return the singleton instance of StaticIpNumberPacketFactory. */
  public static StaticIpNumberPacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpNumber...)} and exists only
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
   * This method is a variant of {@link #newInstance(byte[], int, int, IpNumber...)} and exists only
   * for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, IpNumber number) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 0:
          return IpV6ExtHopByHopOptionsPacket.newPacket(rawData, offset, length);
        case 1:
          return IcmpV4CommonPacket.newPacket(rawData, offset, length);
        case 6:
          return TcpPacket.newPacket(rawData, offset, length);
        case 17:
          return UdpPacket.newPacket(rawData, offset, length);
        case 43:
          return IpV6ExtRoutingPacket.newPacket(rawData, offset, length);
        case 44:
          return IpV6ExtFragmentPacket.newPacket(rawData, offset, length);
        case 58:
          return IcmpV6CommonPacket.newPacket(rawData, offset, length);
        case 59:
          return UnknownPacket.newPacket(rawData, offset, length);
        case 60:
          return IpV6ExtDestinationOptionsPacket.newPacket(rawData, offset, length);
        case 132:
          return SctpPacket.newPacket(rawData, offset, length);
          //          case 255:
          //            255 conflicts with UnknownIpV6Extension
          //            break;
      }
      if (number == UnknownIpV6Extension.getInstance()) {
        return IpV6ExtUnknownPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpNumber...)} and exists only
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
      byte[] rawData, int offset, int length, IpNumber number1, IpNumber number2) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 0:
          return IpV6ExtHopByHopOptionsPacket.newPacket(rawData, offset, length);
        case 1:
          return IcmpV4CommonPacket.newPacket(rawData, offset, length);
        case 6:
          return TcpPacket.newPacket(rawData, offset, length);
        case 17:
          return UdpPacket.newPacket(rawData, offset, length);
        case 43:
          return IpV6ExtRoutingPacket.newPacket(rawData, offset, length);
        case 44:
          return IpV6ExtFragmentPacket.newPacket(rawData, offset, length);
        case 58:
          return IcmpV6CommonPacket.newPacket(rawData, offset, length);
        case 59:
          return UnknownPacket.newPacket(rawData, offset, length);
        case 60:
          return IpV6ExtDestinationOptionsPacket.newPacket(rawData, offset, length);
        case 132:
          return SctpPacket.newPacket(rawData, offset, length);
          //          case 255:
          //            255 conflicts with UnknownIpV6Extension
          //            break;
      }
      if (number1 == UnknownIpV6Extension.getInstance()) {
        return IpV6ExtUnknownPacket.newPacket(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 0:
          return IpV6ExtHopByHopOptionsPacket.newPacket(rawData, offset, length);
        case 1:
          return IcmpV4CommonPacket.newPacket(rawData, offset, length);
        case 6:
          return TcpPacket.newPacket(rawData, offset, length);
        case 17:
          return UdpPacket.newPacket(rawData, offset, length);
        case 43:
          return IpV6ExtRoutingPacket.newPacket(rawData, offset, length);
        case 44:
          return IpV6ExtFragmentPacket.newPacket(rawData, offset, length);
        case 58:
          return IcmpV6CommonPacket.newPacket(rawData, offset, length);
        case 59:
          return UnknownPacket.newPacket(rawData, offset, length);
        case 60:
          return IpV6ExtDestinationOptionsPacket.newPacket(rawData, offset, length);
        case 132:
          return SctpPacket.newPacket(rawData, offset, length);
          //          case 255:
          //            255 conflicts with UnknownIpV6Extension
          //            break;
      }
      if (number2 == UnknownIpV6Extension.getInstance()) {
        return IpV6ExtUnknownPacket.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, IpNumber... numbers) {
    try {
      for (IpNumber num : numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV6ExtHopByHopOptionsPacket.newPacket(rawData, offset, length);
          case 1:
            return IcmpV4CommonPacket.newPacket(rawData, offset, length);
          case 6:
            return TcpPacket.newPacket(rawData, offset, length);
          case 17:
            return UdpPacket.newPacket(rawData, offset, length);
          case 43:
            return IpV6ExtRoutingPacket.newPacket(rawData, offset, length);
          case 44:
            return IpV6ExtFragmentPacket.newPacket(rawData, offset, length);
          case 58:
            return IcmpV6CommonPacket.newPacket(rawData, offset, length);
          case 59:
            return UnknownPacket.newPacket(rawData, offset, length);
          case 60:
            return IpV6ExtDestinationOptionsPacket.newPacket(rawData, offset, length);
          case 132:
            return SctpPacket.newPacket(rawData, offset, length);
            //          case 255:
            //            255 conflicts with UnknownIpV6Extension
            //            break;
        }
        if (num == UnknownIpV6Extension.getInstance()) {
          return IpV6ExtUnknownPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
