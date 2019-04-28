/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

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
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4OptionFactory implements PacketFactory<IpV4Option, IpV4OptionType> {

  private static final StaticIpV4OptionFactory INSTANCE = new StaticIpV4OptionFactory();
  private final Map<IpV4OptionType, Instantiater> instantiaters =
      new HashMap<IpV4OptionType, Instantiater>();

  private StaticIpV4OptionFactory() {
    instantiaters.put(
        IpV4OptionType.END_OF_OPTION_LIST,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4EndOfOptionList.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4EndOfOptionList> getTargetClass() {
            return IpV4EndOfOptionList.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.NO_OPERATION,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4NoOperationOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4NoOperationOption> getTargetClass() {
            return IpV4NoOperationOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.SECURITY,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4Rfc791SecurityOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4Rfc791SecurityOption> getTargetClass() {
            return IpV4Rfc791SecurityOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.LOOSE_SOURCE_ROUTING,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4LooseSourceRouteOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4LooseSourceRouteOption> getTargetClass() {
            return IpV4LooseSourceRouteOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.INTERNET_TIMESTAMP,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4InternetTimestampOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4InternetTimestampOption> getTargetClass() {
            return IpV4InternetTimestampOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.RECORD_ROUTE,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4RecordRouteOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4RecordRouteOption> getTargetClass() {
            return IpV4RecordRouteOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.STREAM_ID,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4StreamIdOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4StreamIdOption> getTargetClass() {
            return IpV4StreamIdOption.class;
          }
        });
    instantiaters.put(
        IpV4OptionType.STRICT_SOURCE_ROUTING,
        new Instantiater() {
          @Override
          public IpV4Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4StrictSourceRouteOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4StrictSourceRouteOption> getTargetClass() {
            return IpV4StrictSourceRouteOption.class;
          }
        });
  };

  /** @return the singleton instance of StaticIpV4OptionFactory. */
  public static StaticIpV4OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV4Option newInstance(byte[] rawData, int offset, int length, IpV4OptionType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData, offset, length);
      }
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV4Option newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV4Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4Option.newInstance(rawData, offset, length);
    }
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass(IpV4OptionType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass() {
    return UnknownIpV4Option.class;
  }

  private static interface Instantiater {

    public IpV4Option newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends IpV4Option> getTargetClass();
  }
}
