/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.namednumber.NA;

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

  @Override
  @Deprecated
  public IpV6TrafficClass newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  @Override
  public IpV6TrafficClass newInstance(byte[] rawData) {
    if (rawData == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    return IpV6SimpleTrafficClass.newInstance(rawData[0]);
  }

  @Override
  @Deprecated
  public Class<? extends IpV6TrafficClass> getTargetClass(NA number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV6TrafficClass> getTargetClass() {
    return IpV6SimpleTrafficClass.class;
  }

}
