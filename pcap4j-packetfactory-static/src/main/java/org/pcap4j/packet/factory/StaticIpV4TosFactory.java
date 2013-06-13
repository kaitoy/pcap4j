/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import static org.pcap4j.util.ByteArrays.*;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4TosFactory
implements ClassifiedDataFactory<IpV4Tos, NA> {

  private static final StaticIpV4TosFactory INSTANCE
    = new StaticIpV4TosFactory();

  /**
   *
   * @return the singleton instance of StaticIpV4TosFactory.
   */
  public static StaticIpV4TosFactory getInstance() {
    return INSTANCE;
  }

  public IpV4Tos newData(byte[] rawData, NA number) {
    return newData(rawData);
  }

  public IpV4Tos newData(byte[] rawData) {
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

    return IpV4Rfc1349Tos.newInstance(rawData[0]);
  }

}
