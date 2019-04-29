/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalIpV4Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4EndOfOptionList;
import org.pcap4j.packet.IpV4InternetTimestampOption;
import org.pcap4j.packet.IpV4LooseSourceRouteOption;
import org.pcap4j.packet.IpV4NoOperationOption;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4RecordRouteOption;
import org.pcap4j.packet.IpV4Rfc791SecurityOption;
import org.pcap4j.packet.IpV4StreamIdOption;
import org.pcap4j.packet.IpV4StrictSourceRouteOption;
import org.pcap4j.packet.UnknownIpV4Option;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4OptionFactory implements PacketFactory<IpV4Option, IpV4OptionType> {

  private static final StaticIpV4OptionFactory INSTANCE = new StaticIpV4OptionFactory();

  private StaticIpV4OptionFactory() {}

  /** @return the singleton instance of StaticIpV4OptionFactory. */
  public static StaticIpV4OptionFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV4OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4Option newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV4Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV4OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4Option newInstance(byte[] rawData, int offset, int length, IpV4OptionType number) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 0:
          return IpV4EndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return IpV4NoOperationOption.newInstance(rawData, offset, length);
        case 7:
          return IpV4RecordRouteOption.newInstance(rawData, offset, length);
        case 68:
          return IpV4InternetTimestampOption.newInstance(rawData, offset, length);
        case 130:
          return IpV4Rfc791SecurityOption.newInstance(rawData, offset, length);
        case 131:
          return IpV4LooseSourceRouteOption.newInstance(rawData, offset, length);
        case 136:
          return IpV4StreamIdOption.newInstance(rawData, offset, length);
        case 137:
          return IpV4StrictSourceRouteOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV4Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV4OptionType...)} and
   * exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4Option newInstance(
      byte[] rawData, int offset, int length, IpV4OptionType number1, IpV4OptionType number2) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 0:
          return IpV4EndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return IpV4NoOperationOption.newInstance(rawData, offset, length);
        case 7:
          return IpV4RecordRouteOption.newInstance(rawData, offset, length);
        case 68:
          return IpV4InternetTimestampOption.newInstance(rawData, offset, length);
        case 130:
          return IpV4Rfc791SecurityOption.newInstance(rawData, offset, length);
        case 131:
          return IpV4LooseSourceRouteOption.newInstance(rawData, offset, length);
        case 136:
          return IpV4StreamIdOption.newInstance(rawData, offset, length);
        case 137:
          return IpV4StrictSourceRouteOption.newInstance(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 0:
          return IpV4EndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return IpV4NoOperationOption.newInstance(rawData, offset, length);
        case 7:
          return IpV4RecordRouteOption.newInstance(rawData, offset, length);
        case 68:
          return IpV4InternetTimestampOption.newInstance(rawData, offset, length);
        case 130:
          return IpV4Rfc791SecurityOption.newInstance(rawData, offset, length);
        case 131:
          return IpV4LooseSourceRouteOption.newInstance(rawData, offset, length);
        case 136:
          return IpV4StreamIdOption.newInstance(rawData, offset, length);
        case 137:
          return IpV4StrictSourceRouteOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV4Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public IpV4Option newInstance(byte[] rawData, int offset, int length, IpV4OptionType... numbers) {
    try {
      for (IpV4OptionType num : numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV4EndOfOptionList.newInstance(rawData, offset, length);
          case 1:
            return IpV4NoOperationOption.newInstance(rawData, offset, length);
          case 7:
            return IpV4RecordRouteOption.newInstance(rawData, offset, length);
          case 68:
            return IpV4InternetTimestampOption.newInstance(rawData, offset, length);
          case 130:
            return IpV4Rfc791SecurityOption.newInstance(rawData, offset, length);
          case 131:
            return IpV4LooseSourceRouteOption.newInstance(rawData, offset, length);
          case 136:
            return IpV4StreamIdOption.newInstance(rawData, offset, length);
          case 137:
            return IpV4StrictSourceRouteOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV4Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length, e);
    }
  }
}
