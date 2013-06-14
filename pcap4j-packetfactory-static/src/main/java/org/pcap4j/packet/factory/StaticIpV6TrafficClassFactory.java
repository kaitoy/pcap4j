/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import static org.pcap4j.util.ByteArrays.*;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6TrafficClassFactory
implements PacketFactory<IpV6TrafficClass, NA> {

  private static final StaticIpV6TrafficClassFactory INSTANCE
    = new StaticIpV6TrafficClassFactory();

  /**
   *
   * @return the singleton instance of StaticIpV6TrafficClassFactory.
   */
  public static StaticIpV6TrafficClassFactory getInstance() {
    return INSTANCE;
  }

  public IpV6TrafficClass newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  public IpV6TrafficClass newInstance(byte[] rawData) {
    if (rawData == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length < BYTE_SIZE_IN_BYTES) {
      throw new IllegalRawDataException(
              "rawData is too short: " + ByteArrays.toHexString(rawData, " ")
            );
    }

    return IpV6SimpleTrafficClass.newInstance(rawData[0]);
  }

}
