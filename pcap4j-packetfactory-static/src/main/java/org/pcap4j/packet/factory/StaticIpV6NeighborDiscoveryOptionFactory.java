/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6NeighborDiscoveryMtuOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryPrefixInformationOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryRedirectedHeaderOption;
import org.pcap4j.packet.IpV6NeighborDiscoverySourceLinkLayerAddressOption;
import org.pcap4j.packet.IpV6NeighborDiscoveryTargetLinkLayerAddressOption;
import org.pcap4j.packet.UnknownIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6NeighborDiscoveryOptionFactory
implements PacketFactory<IpV6NeighborDiscoveryOption, IpV6NeighborDiscoveryOptionType> {

  private static final StaticIpV6NeighborDiscoveryOptionFactory INSTANCE
    = new StaticIpV6NeighborDiscoveryOptionFactory();

  private StaticIpV6NeighborDiscoveryOptionFactory() {}

  /**
   * @return the singleton instance of StaticIpV6NeighborDiscoveryOptionFactory.
   */
  public static StaticIpV6NeighborDiscoveryOptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, int offset, int length, IpV6NeighborDiscoveryOptionType... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (IpV6NeighborDiscoveryOptionType num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 1:
            return IpV6NeighborDiscoverySourceLinkLayerAddressOption
                     .newInstance(rawData, offset, length);
          case 2:
            return IpV6NeighborDiscoveryTargetLinkLayerAddressOption
                     .newInstance(rawData, offset, length);
          case 3:
            return IpV6NeighborDiscoveryPrefixInformationOption
                     .newInstance(rawData, offset, length);
          case 4:
            return IpV6NeighborDiscoveryRedirectedHeaderOption.newInstance(rawData, offset, length);
          case 5:
            return IpV6NeighborDiscoveryMtuOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
