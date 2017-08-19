/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  private StaticIpV4InternetTimestampOptionDataFactory() {}

  /**
   * @return the singleton instance of StaticIpV4InternetTimestampOptionDataFactory.
   */
  public static StaticIpV4InternetTimestampOptionDataFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of
   * {@link #newInstance(byte[], int, int, IpV4InternetTimestampOptionFlag...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length) {
    return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
  }

  /**
   * This method is a variant of
   * {@link #newInstance(byte[], int, int, IpV4InternetTimestampOptionFlag...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, int offset, int length, IpV4InternetTimestampOptionFlag number
  ) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 0:
          return IpV4InternetTimestampOptionTimestamps.newInstance(rawData, offset, length);
        case 1:
          return IpV4InternetTimestampOptionTimestampsWithAddresses
            .newInstance(rawData, offset, length);
        case 3:
          return IpV4InternetTimestampOptionAddressPrespecified
            .newInstance(rawData, offset, length);
      }
      return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of
   * {@link #newInstance(byte[], int, int, IpV4InternetTimestampOptionFlag...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, int offset, int length,
    IpV4InternetTimestampOptionFlag number1, IpV4InternetTimestampOptionFlag number2
  ) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 0:
          return IpV4InternetTimestampOptionTimestamps.newInstance(rawData, offset, length);
        case 1:
          return IpV4InternetTimestampOptionTimestampsWithAddresses
            .newInstance(rawData, offset, length);
        case 3:
          return IpV4InternetTimestampOptionAddressPrespecified
            .newInstance(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 0:
          return IpV4InternetTimestampOptionTimestamps.newInstance(rawData, offset, length);
        case 1:
          return IpV4InternetTimestampOptionTimestampsWithAddresses
            .newInstance(rawData, offset, length);
        case 3:
          return IpV4InternetTimestampOptionAddressPrespecified
            .newInstance(rawData, offset, length);
      }
      return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, int offset, int length, IpV4InternetTimestampOptionFlag... numbers
  ) {
    try {
      for (IpV4InternetTimestampOptionFlag num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV4InternetTimestampOptionTimestamps.newInstance(rawData, offset, length);
          case 1:
            return IpV4InternetTimestampOptionTimestampsWithAddresses
                     .newInstance(rawData, offset, length);
          case 3:
            return IpV4InternetTimestampOptionAddressPrespecified
                     .newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length, e);
    }
  }

}
