/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IllegalDnsRData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class PropertiesBasedDnsRDataFactory
    extends AbstractPropertiesBasedFactory<DnsRData, DnsResourceRecordType> {

  private static final PropertiesBasedDnsRDataFactory INSTANCE =
      new PropertiesBasedDnsRDataFactory();

  private PropertiesBasedDnsRDataFactory() {}

  /** @return the singleton instance of PropertiesBasedDnsRDataFactory. */
  public static PropertiesBasedDnsRDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends DnsRData> getTargetClass(DnsResourceRecordType number) {
    return PacketFactoryPropertiesLoader.getInstance().getDnsRDataClass(number);
  }

  @Override
  protected Class<? extends DnsRData> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownDnsRDataClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected DnsRData newIllegalData(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    return IllegalDnsRData.newInstance(rawData, offset, length, cause);
  }
}
