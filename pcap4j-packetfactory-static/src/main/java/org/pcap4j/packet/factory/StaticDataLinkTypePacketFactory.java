/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.BsdLoopbackPacket;
import org.pcap4j.packet.Dot11Selector;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.HdlcPppPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpSelector;
import org.pcap4j.packet.LinuxSllPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PppSelector;
import org.pcap4j.packet.RadiotapPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticDataLinkTypePacketFactory implements PacketFactory<Packet, DataLinkType> {

  private static final StaticDataLinkTypePacketFactory INSTANCE =
      new StaticDataLinkTypePacketFactory();

  private static final int RAW = DataLinkType.RAW.value();

  private StaticDataLinkTypePacketFactory() {}

  /** @return the singleton instance of StaticDataLinkTypePacketFactory. */
  public static StaticDataLinkTypePacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, DataLinkType...)} and exists
   * only for performance reason.
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
   * This method is a variant of {@link #newInstance(byte[], int, int, DataLinkType...)} and exists
   * only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(byte[] rawData, int offset, int length, DataLinkType number) {
    try {
      int val = number.value();
      switch (val) {
        case 0:
          return BsdLoopbackPacket.newPacket(rawData, offset, length);
        case 1:
          return EthernetPacket.newPacket(rawData, offset, length);
        case 9:
          return PppSelector.newPacket(rawData, offset, length);
        case 50:
          return HdlcPppPacket.newPacket(rawData, offset, length);
        case 105:
          return Dot11Selector.newPacket(rawData, offset, length);
        case 113:
          return LinuxSllPacket.newPacket(rawData, offset, length);
        case 127:
          return RadiotapPacket.newPacket(rawData, offset, length);
      }
      if (RAW == val) {
        return IpSelector.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, DataLinkType...)} and exists
   * only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public Packet newInstance(
      byte[] rawData, int offset, int length, DataLinkType number1, DataLinkType number2) {
    try {
      int val = number1.value();
      switch (val) {
        case 0:
          return BsdLoopbackPacket.newPacket(rawData, offset, length);
        case 1:
          return EthernetPacket.newPacket(rawData, offset, length);
        case 9:
          return PppSelector.newPacket(rawData, offset, length);
        case 50:
          return HdlcPppPacket.newPacket(rawData, offset, length);
        case 105:
          return Dot11Selector.newPacket(rawData, offset, length);
        case 113:
          return LinuxSllPacket.newPacket(rawData, offset, length);
        case 127:
          return RadiotapPacket.newPacket(rawData, offset, length);
      }
      if (RAW == val) {
        return IpSelector.newPacket(rawData, offset, length);
      }

      val = number2.value();
      switch (val) {
        case 0:
          return BsdLoopbackPacket.newPacket(rawData, offset, length);
        case 1:
          return EthernetPacket.newPacket(rawData, offset, length);
        case 9:
          return PppSelector.newPacket(rawData, offset, length);
        case 50:
          return HdlcPppPacket.newPacket(rawData, offset, length);
        case 105:
          return Dot11Selector.newPacket(rawData, offset, length);
        case 113:
          return LinuxSllPacket.newPacket(rawData, offset, length);
        case 127:
          return RadiotapPacket.newPacket(rawData, offset, length);
      }
      if (RAW == val) {
        return IpSelector.newPacket(rawData, offset, length);
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, DataLinkType... numbers) {
    try {
      for (DataLinkType num : numbers) {
        int val = num.value();
        switch (val) {
          case 0:
            return BsdLoopbackPacket.newPacket(rawData, offset, length);
          case 1:
            return EthernetPacket.newPacket(rawData, offset, length);
          case 9:
            return PppSelector.newPacket(rawData, offset, length);
          case 50:
            return HdlcPppPacket.newPacket(rawData, offset, length);
          case 105:
            return Dot11Selector.newPacket(rawData, offset, length);
          case 113:
            return LinuxSllPacket.newPacket(rawData, offset, length);
          case 127:
            return RadiotapPacket.newPacket(rawData, offset, length);
        }
        if (RAW == val) {
          return IpSelector.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }
}
