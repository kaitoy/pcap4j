/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalIpV6RoutingData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6RoutingSourceRouteData;
import org.pcap4j.packet.UnknownIpV6RoutingData;
import org.pcap4j.packet.namednumber.IpV6RoutingType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6RoutingDataFactory
implements PacketFactory<IpV6RoutingData, IpV6RoutingType> {

  private static final StaticIpV6RoutingDataFactory INSTANCE
    = new StaticIpV6RoutingDataFactory();

  private StaticIpV6RoutingDataFactory() {}

  /**
   * @return the singleton instance of StaticIpV6RoutingDataFactory.
   */
  public static StaticIpV6RoutingDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6RoutingData newInstance(
    byte[] rawData, int offset, int length, IpV6RoutingType... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (IpV6RoutingType num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV6RoutingSourceRouteData.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV6RoutingData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData, offset, length, e);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
