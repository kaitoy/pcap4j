/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalIpV4InternetTimestampOptionData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class PropertiesBasedIpV4InternetTimestampOptionDataFactory
extends AbstractPropertiesBasedFactory<
  IpV4InternetTimestampOptionData,
  IpV4InternetTimestampOptionFlag
> {

  private static final PropertiesBasedIpV4InternetTimestampOptionDataFactory INSTANCE
    = new PropertiesBasedIpV4InternetTimestampOptionDataFactory();

  private PropertiesBasedIpV4InternetTimestampOptionDataFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV4InternetTimestampDataFactory.
   */
  public static PropertiesBasedIpV4InternetTimestampOptionDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends IpV4InternetTimestampOptionData>
  getTargetClass(IpV4InternetTimestampOptionFlag flag) {
    return PacketFactoryPropertiesLoader.getInstance()
             .getIpV4InternetTimestampDataClass(flag);
  }

  @Override
  protected Class<? extends IpV4InternetTimestampOptionData> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance()
             .getUnknownIpV4InternetTimestampDataClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected IpV4InternetTimestampOptionData newIllegalData(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length, cause);
  }

}
