/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalIpV6RoutingData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.namednumber.IpV6RoutingType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class
PropertiesBasedIpV6RoutingDataFactory
extends AbstractPropertiesBasedFactory<IpV6RoutingData, IpV6RoutingType> {

  private static final PropertiesBasedIpV6RoutingDataFactory INSTANCE
    = new PropertiesBasedIpV6RoutingDataFactory();

  private PropertiesBasedIpV6RoutingDataFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6RoutingDataFactory.
   */
  public static PropertiesBasedIpV6RoutingDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends IpV6RoutingData> getTargetClass(IpV6RoutingType type) {
    return PacketFactoryPropertiesLoader.getInstance().getIpV6RoutingDataClass(type);
  }

  @Override
  protected Class<? extends IpV6RoutingData> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV6RoutingDataClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected IpV6RoutingData newIllegalData(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    return IllegalIpV6RoutingData.newInstance(rawData, offset, length, cause);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
