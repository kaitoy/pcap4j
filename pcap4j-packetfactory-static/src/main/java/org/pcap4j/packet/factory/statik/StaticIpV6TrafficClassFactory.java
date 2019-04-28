/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6TrafficClassFactory
    implements PacketFactory<IpV6TrafficClass, NotApplicable> {

  private static final StaticIpV6TrafficClassFactory INSTANCE = new StaticIpV6TrafficClassFactory();

  /** @return the singleton instance of StaticIpV6TrafficClassFactory. */
  public static StaticIpV6TrafficClassFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV6TrafficClass newInstance(
      byte[] rawData, int offset, int length, NotApplicable number) {
    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV6TrafficClass newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return IpV6SimpleTrafficClass.newInstance(rawData[offset]);
  }

  @Override
  @Deprecated
  public Class<? extends IpV6TrafficClass> getTargetClass(NotApplicable number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV6TrafficClass> getTargetClass() {
    return IpV6SimpleTrafficClass.class;
  }
}
