/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.namednumber.NA;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4TosFactory implements PacketFactory<IpV4Tos, NA> {

  private static final StaticIpV4TosFactory INSTANCE
    = new StaticIpV4TosFactory();

  /**
   *
   * @return the singleton instance of StaticIpV4TosFactory.
   */
  public static StaticIpV4TosFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV4Tos newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  @Override
  public IpV4Tos newInstance(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    return IpV4Rfc1349Tos.newInstance(rawData[0]);
  }

  @Override
  @Deprecated
  public Class<? extends IpV4Tos> getTargetClass(NA number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV4Tos> getTargetClass() {
    return IpV4Rfc1349Tos.class;
  }

}
