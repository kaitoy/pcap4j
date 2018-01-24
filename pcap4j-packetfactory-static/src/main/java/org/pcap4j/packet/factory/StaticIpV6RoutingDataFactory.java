/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6RoutingType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6RoutingData newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV6RoutingData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6RoutingType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6RoutingData newInstance(
    byte[] rawData, int offset, int length, IpV6RoutingType number
  ) {
    try {
      switch (Byte.toUnsignedInt(number.value())) {
        case 0:
          return IpV6RoutingSourceRouteData.newInstance(rawData, offset, length);
      }
      return UnknownIpV6RoutingData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, IpV6RoutingType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6RoutingData newInstance(
    byte[] rawData, int offset, int length, IpV6RoutingType number1, IpV6RoutingType number2
  ) {
    try {
      switch (Byte.toUnsignedInt(number1.value())) {
        case 0:
          return IpV6RoutingSourceRouteData.newInstance(rawData, offset, length);
      }

      switch (Byte.toUnsignedInt(number2.value())) {
        case 0:
          return IpV6RoutingSourceRouteData.newInstance(rawData, offset, length);
      }
      return UnknownIpV6RoutingData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6RoutingData.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public IpV6RoutingData newInstance(
    byte[] rawData, int offset, int length, IpV6RoutingType... numbers
  ) {
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

}
