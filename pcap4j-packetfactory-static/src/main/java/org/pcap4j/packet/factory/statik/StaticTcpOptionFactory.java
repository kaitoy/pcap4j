/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalTcpOption;
import org.pcap4j.packet.TcpEndOfOptionList;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpNoOperationOption;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.TcpSackOption;
import org.pcap4j.packet.TcpSackPermittedOption;
import org.pcap4j.packet.TcpTimestampsOption;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.UnknownTcpOption;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticTcpOptionFactory implements PacketFactory<TcpOption, TcpOptionKind> {

  private static final StaticTcpOptionFactory INSTANCE = new StaticTcpOptionFactory();

  private StaticTcpOptionFactory() {}

  /** @return the singleton instance of StaticTcpOptionFactory. */
  public static StaticTcpOptionFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, TcpOptionKind...)} and exists
   * only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public TcpOption newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownTcpOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, TcpOptionKind...)} and exists
   * only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public TcpOption newInstance(byte[] rawData, int offset, int length, TcpOptionKind number) {
    try {
      switch (number.value() & 0xff) {
        case 0:
          return TcpEndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return TcpNoOperationOption.newInstance(rawData, offset, length);
        case 2:
          return TcpMaximumSegmentSizeOption.newInstance(rawData, offset, length);
        case 3:
          return TcpWindowScaleOption.newInstance(rawData, offset, length);
        case 4:
          return TcpSackPermittedOption.newInstance(rawData, offset, length);
        case 5:
          return TcpSackOption.newInstance(rawData, offset, length);
        case 8:
          return TcpTimestampsOption.newInstance(rawData, offset, length);
      }
      return UnknownTcpOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, TcpOptionKind...)} and exists
   * only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public TcpOption newInstance(
      byte[] rawData, int offset, int length, TcpOptionKind number1, TcpOptionKind number2) {
    try {
      switch (number1.value() & 0xff) {
        case 0:
          return TcpEndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return TcpNoOperationOption.newInstance(rawData, offset, length);
        case 2:
          return TcpMaximumSegmentSizeOption.newInstance(rawData, offset, length);
        case 3:
          return TcpWindowScaleOption.newInstance(rawData, offset, length);
        case 4:
          return TcpSackPermittedOption.newInstance(rawData, offset, length);
        case 5:
          return TcpSackOption.newInstance(rawData, offset, length);
        case 8:
          return TcpTimestampsOption.newInstance(rawData, offset, length);
      }

      switch (number2.value() & 0xff) {
        case 0:
          return TcpEndOfOptionList.newInstance(rawData, offset, length);
        case 1:
          return TcpNoOperationOption.newInstance(rawData, offset, length);
        case 2:
          return TcpMaximumSegmentSizeOption.newInstance(rawData, offset, length);
        case 3:
          return TcpWindowScaleOption.newInstance(rawData, offset, length);
        case 4:
          return TcpSackPermittedOption.newInstance(rawData, offset, length);
        case 5:
          return TcpSackOption.newInstance(rawData, offset, length);
        case 8:
          return TcpTimestampsOption.newInstance(rawData, offset, length);
      }
      return UnknownTcpOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public TcpOption newInstance(byte[] rawData, int offset, int length, TcpOptionKind... numbers) {
    try {
      for (TcpOptionKind num : numbers) {
        switch (num.value() & 0xff) {
          case 0:
            return TcpEndOfOptionList.newInstance(rawData, offset, length);
          case 1:
            return TcpNoOperationOption.newInstance(rawData, offset, length);
          case 2:
            return TcpMaximumSegmentSizeOption.newInstance(rawData, offset, length);
          case 3:
            return TcpWindowScaleOption.newInstance(rawData, offset, length);
          case 4:
            return TcpSackPermittedOption.newInstance(rawData, offset, length);
          case 5:
            return TcpSackOption.newInstance(rawData, offset, length);
          case 8:
            return TcpTimestampsOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownTcpOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData, offset, length, e);
    }
  }
}
