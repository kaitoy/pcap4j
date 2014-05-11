/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
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
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4OptionFactory
implements PacketFactory<IpV4Option, IpV4OptionType> {

  private static final StaticIpV4OptionFactory INSTANCE
    = new StaticIpV4OptionFactory();
  private final Map<IpV4OptionType, Instantiater> instantiaters
    = new HashMap<IpV4OptionType, Instantiater>();

  private StaticIpV4OptionFactory() {
    instantiaters.put(
      IpV4OptionType.END_OF_OPTION_LIST, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4EndOfOptionList.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.NO_OPERATION, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4NoOperationOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.SECURITY, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4Rfc791SecurityOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.LOOSE_SOURCE_ROUTING, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4LooseSourceRouteOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.INTERNET_TIMESTAMP, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4InternetTimestampOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.RECORD_ROUTE, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4RecordRouteOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.STREAM_ID, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4StreamIdOption.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4OptionType.STRICT_SOURCE_ROUTING, new Instantiater() {
        @Override
        public IpV4Option newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4StrictSourceRouteOption.newInstance(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIpV4OptionFactory.
   */
  public static StaticIpV4OptionFactory getInstance() {
    return INSTANCE;
  }

  public IpV4Option newInstance(byte[] rawData, IpV4OptionType number) {
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
      return IllegalIpV4Option.newInstance(rawData);
    }

    return newInstance(rawData);
  }

  public IpV4Option newInstance(byte[] rawData) {
    try {
      return UnknownIpV4Option.newInstance(rawData);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData);
    }
  }

  private static abstract class Instantiater {

    public abstract IpV4Option newInstance(byte [] rawData) throws IllegalRawDataException;

  }

}
