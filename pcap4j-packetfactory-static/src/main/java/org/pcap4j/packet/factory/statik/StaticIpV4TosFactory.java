/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4TosFactory implements PacketFactory<IpV4Tos, NotApplicable> {

  private static final StaticIpV4TosFactory INSTANCE = new StaticIpV4TosFactory();

  /** @return the singleton instance of StaticIpV4TosFactory. */
  public static StaticIpV4TosFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV4Tos newInstance(byte[] rawData, int offset, int length, NotApplicable number) {
    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV4Tos newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return IpV4Rfc1349Tos.newInstance(rawData[offset]);
  }

  @Override
  @Deprecated
  public Class<? extends IpV4Tos> getTargetClass(NotApplicable number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV4Tos> getTargetClass() {
    return IpV4Rfc1349Tos.class;
  }
}
