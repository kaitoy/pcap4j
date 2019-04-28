/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IllegalDnsRData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class PropertiesBasedDnsRDataFactory
    implements PacketFactory<DnsRData, DnsResourceRecordType> {

  private static final PropertiesBasedDnsRDataFactory INSTANCE =
      new PropertiesBasedDnsRDataFactory();

  private PropertiesBasedDnsRDataFactory() {}

  /** @return the singleton instance of PropertiesBasedDnsRDataFactory. */
  public static PropertiesBasedDnsRDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public DnsRData newInstance(byte[] rawData, int offset, int length, DnsResourceRecordType num) {
    return newInstance(rawData, offset, length, getTargetClass(num));
  }

  @Override
  public DnsRData newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new DnsRDataField object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public DnsRData newInstance(
      byte[] rawData, int offset, int length, Class<? extends DnsRData> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (DnsRData) newInstance.invoke(null, rawData, offset, length);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      if (e.getTargetException() instanceof IllegalRawDataException) {
        return IllegalDnsRData.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends DnsRData> getTargetClass(DnsResourceRecordType num) {
    if (num == null) {
      throw new NullPointerException("num must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance().getDnsRDataClass(num);
  }

  @Override
  public Class<? extends DnsRData> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownDnsRDataClass();
  }
}
