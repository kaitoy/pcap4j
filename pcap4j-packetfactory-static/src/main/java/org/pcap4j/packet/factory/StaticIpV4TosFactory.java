/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV4TosFactory implements PacketFactory<IpV4Tos, NotApplicable> {

  private static final StaticIpV4TosFactory INSTANCE = new StaticIpV4TosFactory();

  private StaticIpV4TosFactory() {}

  /**
   * @return the singleton instance of StaticIpV4TosFactory.
   */
  public static StaticIpV4TosFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV4Tos newInstance(byte[] rawData, int offset, int length, NotApplicable... numbers) {
    ByteArrays.validateBounds(rawData, offset, length);
    return IpV4Rfc1349Tos.newInstance(rawData[offset]);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
