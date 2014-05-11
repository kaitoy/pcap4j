/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalIpV4InternetTimestampOptionData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.IpV4InternetTimestampOptionAddressPrespecified;
import org.pcap4j.packet.IpV4InternetTimestampOptionTimestamps;
import org.pcap4j.packet.IpV4InternetTimestampOptionTimestampsWithAddresses;
import org.pcap4j.packet.UnknownIpV4InternetTimestampOptionData;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4InternetTimestampOptionDataFactory
implements PacketFactory<IpV4InternetTimestampOptionData, IpV4InternetTimestampOptionFlag> {

  private static final StaticIpV4InternetTimestampOptionDataFactory INSTANCE
    = new StaticIpV4InternetTimestampOptionDataFactory();
  private final Map<IpV4InternetTimestampOptionFlag, Instantiater> instantiaters
    = new HashMap<IpV4InternetTimestampOptionFlag, Instantiater>();

  private StaticIpV4InternetTimestampOptionDataFactory() {
    instantiaters.put(
      IpV4InternetTimestampOptionFlag.TIMESTAMPS_ONLY, new Instantiater() {
        @Override
        public IpV4InternetTimestampOptionData newInstance(
          byte[] rawData
        ) throws IllegalRawDataException {
          return IpV4InternetTimestampOptionTimestamps.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4InternetTimestampOptionFlag.EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS, new Instantiater() {
        @Override
        public IpV4InternetTimestampOptionData newInstance(
          byte[] rawData
        ) throws IllegalRawDataException {
          return IpV4InternetTimestampOptionTimestampsWithAddresses.newInstance(rawData);
        }
      }
    );
    instantiaters.put(
      IpV4InternetTimestampOptionFlag.ADDRESS_PRESPECIFIED, new Instantiater() {
        @Override
        public IpV4InternetTimestampOptionData newInstance(
          byte[] rawData
        ) throws IllegalRawDataException {
          return IpV4InternetTimestampOptionAddressPrespecified.newInstance(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIpV4InternetTimestampOptionDataFactory.
   */
  public static StaticIpV4InternetTimestampOptionDataFactory getInstance() {
    return INSTANCE;
  }

  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, IpV4InternetTimestampOptionFlag number
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
      return IllegalIpV4InternetTimestampOptionData.newInstance(rawData);
    }

    return UnknownIpV4InternetTimestampOptionData.newInstance(rawData);
  }

  public IpV4InternetTimestampOptionData newInstance(byte[] rawData) {
    return UnknownIpV4InternetTimestampOptionData.newInstance(rawData);
  }

  private static abstract class Instantiater {

    public abstract IpV4InternetTimestampOptionData newInstance(
      byte [] rawData
    ) throws IllegalRawDataException;

  }

}
