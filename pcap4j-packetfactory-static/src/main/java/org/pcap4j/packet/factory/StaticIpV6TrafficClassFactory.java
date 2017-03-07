/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6TrafficClassFactory
implements PacketFactory<IpV6TrafficClass, NotApplicable> {

  private static final StaticIpV6TrafficClassFactory INSTANCE
    = new StaticIpV6TrafficClassFactory();

  private StaticIpV6TrafficClassFactory() {}

  /**
   * @return the singleton instance of StaticIpV6TrafficClassFactory.
   */
  public static StaticIpV6TrafficClassFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6TrafficClass newInstance(
    byte[] rawData, int offset, int length, NotApplicable... numbers
  ) {
    ByteArrays.validateBounds(rawData, offset, length);
    return IpV6SimpleTrafficClass.newInstance(rawData[offset]);
  }

}
