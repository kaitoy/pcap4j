/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
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
public final class StaticTcpOptionFactory
implements PacketFactory<TcpOption, TcpOptionKind> {

  private static final StaticTcpOptionFactory INSTANCE
    = new StaticTcpOptionFactory();
  private final Map<TcpOptionKind, Instantiater> instantiaters
    = new HashMap<TcpOptionKind, Instantiater>();

  private StaticTcpOptionFactory() {
    instantiaters.put(
      TcpOptionKind.END_OF_OPTION_LIST, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpEndOfOptionList.newInstance(rawData);
        }
        @Override
        public Class<TcpEndOfOptionList> getTargetClass() {
          return TcpEndOfOptionList.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.NO_OPERATION, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpNoOperationOption.newInstance(rawData);
        }
        @Override
        public Class<TcpNoOperationOption> getTargetClass() {
          return TcpNoOperationOption.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.MAXIMUM_SEGMENT_SIZE, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpMaximumSegmentSizeOption.newInstance(rawData);
        }
        @Override
        public Class<TcpMaximumSegmentSizeOption> getTargetClass() {
          return TcpMaximumSegmentSizeOption.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.WINDOW_SCALE, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpWindowScaleOption.newInstance(rawData);
        }
        @Override
        public Class<TcpWindowScaleOption> getTargetClass() {
          return TcpWindowScaleOption.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.SACK_PERMITTED, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpSackPermittedOption.newInstance(rawData);
        }
        @Override
        public Class<TcpSackPermittedOption> getTargetClass() {
          return TcpSackPermittedOption.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.SACK, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpSackOption.newInstance(rawData);
        }
        @Override
        public Class<TcpSackOption> getTargetClass() {
          return TcpSackOption.class;
        }
      }
    );
    instantiaters.put(
      TcpOptionKind.TIMESTAMPS, new Instantiater() {
        @Override
        public TcpOption newInstance(byte[] rawData) throws IllegalRawDataException {
          return TcpTimestampsOption.newInstance(rawData);
        }
        @Override
        public Class<TcpTimestampsOption> getTargetClass() {
          return TcpTimestampsOption.class;
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

  @Override
  public TcpOption newInstance(
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

    return newInstance(rawData);
  }

  @Override
  public TcpOption newInstance(byte[] rawData) {
    try {
      return UnknownTcpOption.newInstance(rawData);
    } catch (IllegalRawDataException e) {
      return IllegalTcpOption.newInstance(rawData);
    }
  }

  @Override
  public Class<? extends TcpOption> getTargetClass(TcpOptionKind number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends TcpOption> getTargetClass() {
    return UnknownTcpOption.class;
  }

  private static interface Instantiater {

    public TcpOption newInstance(byte [] rawData) throws IllegalRawDataException;

    public Class<? extends TcpOption> getTargetClass();

  }

}
