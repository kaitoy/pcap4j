/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6OptionFactory
    extends AbstractPropertiesBasedFactory<IpV6Option, IpV6OptionType> {

  private static final PropertiesBasedIpV6OptionFactory INSTANCE =
      new PropertiesBasedIpV6OptionFactory();

  private PropertiesBasedIpV6OptionFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV6OptionFactory. */
  public static PropertiesBasedIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends IpV6Option> getTargetClass(IpV6OptionType number) {
    return PacketFactoryPropertiesLoader.getInstance().getIpV6OptionClass(number);
  }

  @Override
  protected Class<? extends IpV6Option> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV6OptionClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected IpV6Option newIllegalData(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    return IllegalIpV6Option.newInstance(rawData, offset, length, cause);
  }
}
