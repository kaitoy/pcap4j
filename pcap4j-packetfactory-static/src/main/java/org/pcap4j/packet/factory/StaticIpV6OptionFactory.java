/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6Pad1Option;
import org.pcap4j.packet.IpV6PadNOption;
import org.pcap4j.packet.UnknownIpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6OptionFactory implements PacketFactory<IpV6Option, IpV6OptionType> {

  private static final StaticIpV6OptionFactory INSTANCE = new StaticIpV6OptionFactory();

  private StaticIpV6OptionFactory() {}

  /** @return the singleton instance of StaticIpV6OptionFactory. */
  public static StaticIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6Option newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6Option newInstance(byte[] rawData, int offset, int length, IpV6OptionType number) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 0:
          return IpV6Pad1Option.newInstance(rawData, offset, length);
        case 1:
          return IpV6PadNOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6Option newInstance(
      byte[] rawData, int offset, int length, IpV6OptionType number1, IpV6OptionType number2) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 0:
          return IpV6Pad1Option.newInstance(rawData, offset, length);
        case 1:
          return IpV6PadNOption.newInstance(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 0:
          return IpV6Pad1Option.newInstance(rawData, offset, length);
        case 1:
          return IpV6PadNOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public IpV6Option newInstance(byte[] rawData, int offset, int length, IpV6OptionType... numbers) {
    try {
      for (IpV6OptionType num : numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV6Pad1Option.newInstance(rawData, offset, length);
          case 1:
            return IpV6PadNOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length, e);
    }
  }
}
