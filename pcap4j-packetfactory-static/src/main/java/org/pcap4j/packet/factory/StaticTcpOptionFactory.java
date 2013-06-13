/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalTcpOption;
import org.pcap4j.packet.TcpEndOfOptionList;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpNoOperationOption;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.UnknownTcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticTcpOptionFactory
implements ClassifiedDataFactory<TcpOption, TcpOptionKind> {

  private static final StaticTcpOptionFactory INSTANCE
    = new StaticTcpOptionFactory();
  private final Map<TcpOptionKind, Instantiater> instantiaters
    = new HashMap<TcpOptionKind, Instantiater>();

  private StaticTcpOptionFactory() {
    instantiaters.put(
      TcpOptionKind.END_OF_OPTION_LIST, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) {
          return TcpEndOfOptionList.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.NO_OPERATION, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) {
          return TcpNoOperationOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.MAXIMUM_SEGMENT_SIZE, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) {
          return TcpMaximumSegmentSizeOption.newInstance(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticTcpOptionFactory.
   */
  public static StaticTcpOptionFactory getInstance() {
    return INSTANCE;
  }

  public TcpOption newData(
    byte[] rawData, TcpOptionKind number
  ) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData);
    }

    return UnknownTcpOption.newInstance(rawData);
  }

  public TcpOption newData(byte[] rawData) {
    return UnknownTcpOption.newInstance(rawData);
  }

  private static abstract class Instantiater {

    public abstract TcpOption newInstance(byte [] rawData);

  }

}
