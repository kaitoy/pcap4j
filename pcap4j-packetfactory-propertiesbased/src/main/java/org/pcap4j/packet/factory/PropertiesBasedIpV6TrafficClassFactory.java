/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.namednumber.NA;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6TrafficClassFactory
implements PacketFactory<IpV6TrafficClass, NA> {

  private static final PropertiesBasedIpV6TrafficClassFactory INSTANCE
    = new PropertiesBasedIpV6TrafficClassFactory();

  private PropertiesBasedIpV6TrafficClassFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6TrafficClassFactory.
   */
  public static PropertiesBasedIpV6TrafficClassFactory getInstance() { return INSTANCE; }

  public IpV6TrafficClass newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  public IpV6TrafficClass newInstance(byte[] rawData) {
    Class<? extends IpV6TrafficClass> clazz
      = PacketFactoryPropertiesLoader.getInstance().getIpV6TrafficClassClass();
    return newInstance(rawData, clazz);
  }

  /**
   *
   * @param rawData
   * @param clazz
   * @return a new IpV6TrafficClass object.
   */
  public IpV6TrafficClass newInstance(
    byte[] rawData, Class<? extends IpV6TrafficClass> clazz
  ) {
    if (rawData == null || clazz == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" clazz: ")
        .append(clazz);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", byte.class);
      return (IpV6TrafficClass)newInstance.invoke(null, rawData[0]);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e.getTargetException());
    }
  }

}
