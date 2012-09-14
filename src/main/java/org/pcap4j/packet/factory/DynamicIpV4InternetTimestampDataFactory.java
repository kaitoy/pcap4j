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
import org.pcap4j.packet.PacketPropertiesLoader;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class
DynamicIpV4InternetTimestampDataFactory
implements ClassifiedDataFactory<IpV4InternetTimestampOptionData, IpV4InternetTimestampOptionFlag> {

  private static final DynamicIpV4InternetTimestampDataFactory INSTANCE
    = new DynamicIpV4InternetTimestampDataFactory();

  private DynamicIpV4InternetTimestampDataFactory() {}

  /**
   *
   * @return
   */
  public static DynamicIpV4InternetTimestampDataFactory getInstance() {
    return INSTANCE;
  }

  public IpV4InternetTimestampOptionData newData(
    byte[] rawData, IpV4InternetTimestampOptionFlag flag
  ) {
    if (flag == null) {
      throw new NullPointerException("flag may not be null");
    }

    Class<? extends IpV4InternetTimestampOptionData> dataClass
      = PacketPropertiesLoader.getInstance().getIpV4InternetTimestampDataClass(flag);
    return newData(rawData, dataClass);
  }

  public IpV4InternetTimestampOptionData newData(byte[] rawData) {
    Class<? extends IpV4InternetTimestampOptionData> dataClass
      = PacketPropertiesLoader.getInstance().getUnknownIpV4InternetTimestampDataClass();
    return newData(rawData, dataClass);
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return
   */
  public IpV4InternetTimestampOptionData newData(
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
