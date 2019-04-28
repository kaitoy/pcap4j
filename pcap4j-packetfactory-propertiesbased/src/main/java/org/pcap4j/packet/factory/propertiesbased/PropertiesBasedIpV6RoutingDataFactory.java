/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV6RoutingData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV6RoutingType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6RoutingDataFactory
    implements PacketFactory<IpV6RoutingData, IpV6RoutingType> {

  private static final PropertiesBasedIpV6RoutingDataFactory INSTANCE =
      new PropertiesBasedIpV6RoutingDataFactory();

  private PropertiesBasedIpV6RoutingDataFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV6RoutingDataFactory. */
  public static PropertiesBasedIpV6RoutingDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6RoutingData newInstance(byte[] rawData, int offset, int length, IpV6RoutingType type) {
    return newInstance(rawData, offset, length, getTargetClass(type));
  }

  @Override
  public IpV6RoutingData newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new IpV6RoutingData object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV6RoutingData newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV6RoutingData> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (IpV6RoutingData) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalIpV6RoutingData.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends IpV6RoutingData> getTargetClass(IpV6RoutingType type) {
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
