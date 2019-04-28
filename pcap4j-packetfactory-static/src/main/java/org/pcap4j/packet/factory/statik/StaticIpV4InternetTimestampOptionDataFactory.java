/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalIpV4InternetTimestampOptionData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.IpV4InternetTimestampOptionAddressPrespecified;
import org.pcap4j.packet.IpV4InternetTimestampOptionTimestamps;
import org.pcap4j.packet.IpV4InternetTimestampOptionTimestampsWithAddresses;
import org.pcap4j.packet.UnknownIpV4InternetTimestampOptionData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4InternetTimestampOptionDataFactory
    implements PacketFactory<IpV4InternetTimestampOptionData, IpV4InternetTimestampOptionFlag> {

  private static final StaticIpV4InternetTimestampOptionDataFactory INSTANCE =
      new StaticIpV4InternetTimestampOptionDataFactory();
  private final Map<IpV4InternetTimestampOptionFlag, Instantiater> instantiaters =
      new HashMap<IpV4InternetTimestampOptionFlag, Instantiater>();

  private StaticIpV4InternetTimestampOptionDataFactory() {
    instantiaters.put(
        IpV4InternetTimestampOptionFlag.TIMESTAMPS_ONLY,
        new Instantiater() {
          @Override
          public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4InternetTimestampOptionTimestamps.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV4InternetTimestampOptionTimestamps> getTargetClass() {
            return IpV4InternetTimestampOptionTimestamps.class;
          }
        });
    instantiaters.put(
        IpV4InternetTimestampOptionFlag.EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS,
        new Instantiater() {
          @Override
          public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4InternetTimestampOptionTimestampsWithAddresses.newInstance(
                rawData, offset, length);
          }

          @Override
          public Class<IpV4InternetTimestampOptionTimestampsWithAddresses> getTargetClass() {
            return IpV4InternetTimestampOptionTimestampsWithAddresses.class;
          }
        });
    instantiaters.put(
        IpV4InternetTimestampOptionFlag.ADDRESS_PRESPECIFIED,
        new Instantiater() {
          @Override
          public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4InternetTimestampOptionAddressPrespecified.newInstance(
                rawData, offset, length);
          }

          @Override
          public Class<IpV4InternetTimestampOptionAddressPrespecified> getTargetClass() {
            return IpV4InternetTimestampOptionAddressPrespecified.class;
          }
        });
  }

  /** @return the singleton instance of StaticIpV4InternetTimestampOptionDataFactory. */
  public static StaticIpV4InternetTimestampOptionDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(
      byte[] rawData, int offset, int length, IpV4InternetTimestampOptionFlag number) {
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
      return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
    }

    return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length) {
    return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData> getTargetClass(
      IpV4InternetTimestampOptionFlag number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData> getTargetClass() {
    return UnknownIpV4InternetTimestampOptionData.class;
  }

  private static interface Instantiater {

    public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends IpV4InternetTimestampOptionData> getTargetClass();
  }
}
