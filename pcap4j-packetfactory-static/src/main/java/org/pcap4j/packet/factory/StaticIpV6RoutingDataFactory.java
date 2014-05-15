/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalIpV6RoutingData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6RoutingSourceRouteData;
import org.pcap4j.packet.UnknownIpV6RoutingData;
import org.pcap4j.packet.namednumber.IpV6RoutingHeaderType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6RoutingDataFactory
implements PacketFactory<IpV6RoutingData, IpV6RoutingHeaderType> {

  private static final StaticIpV6RoutingDataFactory INSTANCE
    = new StaticIpV6RoutingDataFactory();
  private final Map<IpV6RoutingHeaderType, Instantiater> instantiaters
    = new HashMap<IpV6RoutingHeaderType, Instantiater>();

  private StaticIpV6RoutingDataFactory() {
    instantiaters.put(
      IpV6RoutingHeaderType.SOURCE_ROUTE, new Instantiater() {
        @Override
        public IpV6RoutingData newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV6RoutingSourceRouteData.newInstance(rawData);
        }
        @Override
        public Class<IpV6RoutingSourceRouteData> getTargetClass() {
          return IpV6RoutingSourceRouteData.class;
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIpV6RoutingDataFactory.
   */
  public static StaticIpV6RoutingDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6RoutingData newInstance(
    byte[] rawData, IpV6RoutingHeaderType number
  ) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData);
    }

    return newInstance(rawData);
  }

  @Override
  public IpV6RoutingData newInstance(byte[] rawData) {
    try {
      return UnknownIpV6RoutingData.newInstance(rawData);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData);
    }
  }

  @Override
  public Class<? extends IpV6RoutingData> getTargetClass(IpV6RoutingHeaderType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends IpV6RoutingData> getTargetClass() {
    return UnknownIpV6RoutingData.class;
  }

  private static interface Instantiater {

    public IpV6RoutingData newInstance(
      byte [] rawData
    ) throws IllegalRawDataException;

    public Class<? extends IpV6RoutingData> getTargetClass();

  }

}
