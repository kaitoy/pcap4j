/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV4InternetTimestampOptionData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class
PropertiesBasedIpV4InternetTimestampOptionDataFactory
implements PacketFactory<IpV4InternetTimestampOptionData, IpV4InternetTimestampOptionFlag> {

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
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, IpV4InternetTimestampOptionFlag flag
  ) {
    return newInstance(rawData, getTargetClass(flag));
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return a new IpV4InternetTimestampOptionData object.
   */
  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, Class<? extends IpV4InternetTimestampOptionData> dataClass
  ) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" dataClass: ")
        .append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class);
      return (IpV4InternetTimestampOptionData)newInstance.invoke(null, rawData);
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
        return IllegalIpV4InternetTimestampOptionData.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData>
  getTargetClass(IpV4InternetTimestampOptionFlag flag) {
    if (flag == null) {
      throw new NullPointerException("flag must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance()
             .getIpV4InternetTimestampDataClass(flag);
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance()
             .getUnknownIpV4InternetTimestampDataClass();
  }

}
