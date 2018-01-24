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
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class
PropertiesBasedIpV6NeighborDiscoveryOptionFactory
extends AbstractPropertiesBasedFactory<IpV6NeighborDiscoveryOption, IpV6NeighborDiscoveryOptionType> {

  private static final PropertiesBasedIpV6NeighborDiscoveryOptionFactory INSTANCE
    = new PropertiesBasedIpV6NeighborDiscoveryOptionFactory();

  private PropertiesBasedIpV6NeighborDiscoveryOptionFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6NeighborDiscoveryOptionFactory.
   */
  public static PropertiesBasedIpV6NeighborDiscoveryOptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends IpV6NeighborDiscoveryOption> getTargetClass(
    IpV6NeighborDiscoveryOptionType type
  ) {
    return PacketFactoryPropertiesLoader.getInstance()
             .getIpV6NeighborDiscoveryOptionClass(type);
  }

  @Override
  protected Class<? extends IpV6NeighborDiscoveryOption> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance()
             .getUnknownIpV6NeighborDiscoveryOptionClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected IpV6NeighborDiscoveryOption newIllegalData(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length, cause);
  }

}
