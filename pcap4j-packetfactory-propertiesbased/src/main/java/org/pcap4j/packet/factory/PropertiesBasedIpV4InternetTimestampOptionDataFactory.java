/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
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

  public IpV4InternetTimestampOptionData newInstance(
    byte[] rawData, IpV4InternetTimestampOptionFlag flag
  ) {
    if (flag == null) {
      throw new NullPointerException("flag may not be null");
    }

    Class<? extends IpV4InternetTimestampOptionData> dataClass
      = PacketFactoryPropertiesLoader.getInstance().getIpV4InternetTimestampDataClass(flag);
    return newInstance(rawData, dataClass);
  }

  public IpV4InternetTimestampOptionData newInstance(byte[] rawData) {
    Class<? extends IpV4InternetTimestampOptionData> dataClass
      = PacketFactoryPropertiesLoader.getInstance().getUnknownIpV4InternetTimestampDataClass();
    return newInstance(rawData, dataClass);
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

}
