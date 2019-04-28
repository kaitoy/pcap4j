/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV4InternetTimestampOptionData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class PropertiesBasedIpV4InternetTimestampOptionDataFactory
    implements PacketFactory<IpV4InternetTimestampOptionData, IpV4InternetTimestampOptionFlag> {

  private static final PropertiesBasedIpV4InternetTimestampOptionDataFactory INSTANCE =
      new PropertiesBasedIpV4InternetTimestampOptionDataFactory();

  private PropertiesBasedIpV4InternetTimestampOptionDataFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV4InternetTimestampDataFactory. */
  public static PropertiesBasedIpV4InternetTimestampOptionDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(
      byte[] rawData, int offset, int length, IpV4InternetTimestampOptionFlag flag) {
    return newInstance(rawData, offset, length, getTargetClass(flag));
  }

  @Override
  public IpV4InternetTimestampOptionData newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new IpV4InternetTimestampOptionData object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV4InternetTimestampOptionData newInstance(
      byte[] rawData,
      int offset,
      int length,
      Class<? extends IpV4InternetTimestampOptionData> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (IpV4InternetTimestampOptionData) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalIpV4InternetTimestampOptionData.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData> getTargetClass(
      IpV4InternetTimestampOptionFlag flag) {
    if (flag == null) {
      throw new NullPointerException("flag must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance().getIpV4InternetTimestampDataClass(flag);
  }

  @Override
  public Class<? extends IpV4InternetTimestampOptionData> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV4InternetTimestampDataClass();
  }
}
