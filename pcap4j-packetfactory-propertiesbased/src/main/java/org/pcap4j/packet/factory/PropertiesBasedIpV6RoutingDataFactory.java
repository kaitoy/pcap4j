/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV6RoutingData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.namednumber.IpV6RoutingHeaderType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class
PropertiesBasedIpV6RoutingDataFactory
implements PacketFactory<IpV6RoutingData, IpV6RoutingHeaderType> {

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
  public IpV6RoutingData newInstance(
    byte[] rawData, IpV6RoutingHeaderType type
  ) {
    return newInstance(rawData, getTargetClass(type));
  }

  @Override
  public IpV6RoutingData newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return a new IpV6RoutingData object.
   */
  public IpV6RoutingData newInstance(
    byte[] rawData, Class<? extends IpV6RoutingData> dataClass
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
      return (IpV6RoutingData)newInstance.invoke(null, rawData);
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
        return IllegalIpV6RoutingData.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  public Class<? extends IpV6RoutingData> getTargetClass(IpV6RoutingHeaderType type) {
    if (type == null) {
      throw new NullPointerException("type must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance().getIpV6RoutingDataClass(type);
  }

  @Override
  public Class<? extends IpV6RoutingData> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV6RoutingDataClass();
  }

}
