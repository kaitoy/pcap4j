/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

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

  @Override
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, int offset, int length, IpV4InternetTimestampOptionFlag... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

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

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
