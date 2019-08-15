/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6NeighborDiscoveryMtuOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryPrefixInformationOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryRedirectedHeaderOption;
import org.pcap4j.packet.IpV6NeighborDiscoverySourceLinkLayerAddressOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryTargetLinkLayerAddressOption;
import org.pcap4j.packet.UnknownIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6NeighborDiscoveryOptionFactory
    implements PacketFactory<IpV6NeighborDiscoveryOption, IpV6NeighborDiscoveryOptionType> {

  private static final StaticIpV6NeighborDiscoveryOptionFactory INSTANCE =
      new StaticIpV6NeighborDiscoveryOptionFactory();

  private StaticIpV6NeighborDiscoveryOptionFactory() {}

  /** @return the singleton instance of StaticIpV6NeighborDiscoveryOptionFactory. */
  public static StaticIpV6NeighborDiscoveryOptionFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int,
   * IpV6NeighborDiscoveryOptionType...)} and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6NeighborDiscoveryOption newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int,
   * IpV6NeighborDiscoveryOptionType...)} and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6NeighborDiscoveryOption newInstance(
      byte[] rawData, int offset, int length, IpV6NeighborDiscoveryOptionType number) {
    try {
      switch (number.value() & 0xff) {
        case 1:
          return IpV6NeighborDiscoverySourceLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 2:
          return IpV6NeighborDiscoveryTargetLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 3:
          return IpV6NeighborDiscoveryPrefixInformationOption.newInstance(rawData, offset, length);
        case 4:
          return IpV6NeighborDiscoveryRedirectedHeaderOption.newInstance(rawData, offset, length);
        case 5:
          return IpV6NeighborDiscoveryMtuOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int,
   * IpV6NeighborDiscoveryOptionType...)} and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6NeighborDiscoveryOption newInstance(
      byte[] rawData,
      int offset,
      int length,
      IpV6NeighborDiscoveryOptionType number1,
      IpV6NeighborDiscoveryOptionType number2) {
    try {
      switch (number1.value() & 0xff) {
        case 1:
          return IpV6NeighborDiscoverySourceLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 2:
          return IpV6NeighborDiscoveryTargetLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 3:
          return IpV6NeighborDiscoveryPrefixInformationOption.newInstance(rawData, offset, length);
        case 4:
          return IpV6NeighborDiscoveryRedirectedHeaderOption.newInstance(rawData, offset, length);
        case 5:
          return IpV6NeighborDiscoveryMtuOption.newInstance(rawData, offset, length);
      }

      switch (number2.value() & 0xff) {
        case 1:
          return IpV6NeighborDiscoverySourceLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 2:
          return IpV6NeighborDiscoveryTargetLinkLayerAddressOption.newInstance(
              rawData, offset, length);
        case 3:
          return IpV6NeighborDiscoveryPrefixInformationOption.newInstance(rawData, offset, length);
        case 4:
          return IpV6NeighborDiscoveryRedirectedHeaderOption.newInstance(rawData, offset, length);
        case 5:
          return IpV6NeighborDiscoveryMtuOption.newInstance(rawData, offset, length);
      }
      return UnknownIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public IpV6NeighborDiscoveryOption newInstance(
      byte[] rawData, int offset, int length, IpV6NeighborDiscoveryOptionType... numbers) {
    try {
      for (IpV6NeighborDiscoveryOptionType num : numbers) {
        switch (num.value() & 0xff) {
          case 1:
            return IpV6NeighborDiscoverySourceLinkLayerAddressOption.newInstance(
                rawData, offset, length);
          case 2:
            return IpV6NeighborDiscoveryTargetLinkLayerAddressOption.newInstance(
                rawData, offset, length);
          case 3:
            return IpV6NeighborDiscoveryPrefixInformationOption.newInstance(
                rawData, offset, length);
          case 4:
            return IpV6NeighborDiscoveryRedirectedHeaderOption.newInstance(rawData, offset, length);
          case 5:
            return IpV6NeighborDiscoveryMtuOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length, e);
    }
  }
}
