/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

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
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticTcpOptionFactory implements PacketFactory<TcpOption, TcpOptionKind> {

  private static final StaticTcpOptionFactory INSTANCE = new StaticTcpOptionFactory();

  private StaticTcpOptionFactory() {}

  /**
   *
   * @return the singleton instance of StaticTcpOptionFactory.
   */
  public static StaticTcpOptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public TcpOption newInstance(byte[] rawData, int offset, int length, TcpOptionKind... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (TcpOptionKind num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
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
