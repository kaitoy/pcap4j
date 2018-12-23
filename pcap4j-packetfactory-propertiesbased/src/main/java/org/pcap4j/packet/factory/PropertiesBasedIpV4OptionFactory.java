/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IllegalIpV4Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4OptionFactory
    extends AbstractPropertiesBasedFactory<IpV4Option, IpV4OptionType> {

  private static final PropertiesBasedIpV4OptionFactory INSTANCE =
      new PropertiesBasedIpV4OptionFactory();

  private PropertiesBasedIpV4OptionFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV4OptionFactory. */
  public static PropertiesBasedIpV4OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends IpV4Option> getTargetClass(IpV4OptionType number) {
    return PacketFactoryPropertiesLoader.getInstance().getIpV4OptionClass(number);
  }

  @Override
  protected Class<? extends IpV4Option> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV4OptionClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected IpV4Option newIllegalData(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    return IllegalIpV4Option.newInstance(rawData, offset, length, cause);
  }
}
