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
import org.pcap4j.packet.PacketPropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class DynamicIpV6TrafficClassFactory implements IpV6TrafficClassFactory {

  private static final DynamicIpV6TrafficClassFactory INSTANCE
    = new DynamicIpV6TrafficClassFactory();

  private DynamicIpV6TrafficClassFactory() {}

  /**
   *
   * @return
   */
  public static DynamicIpV6TrafficClassFactory getInstance() { return INSTANCE; }

  public IpV6TrafficClass newTrafficClass(byte value) {
    Class<? extends IpV6TrafficClass> clazz
      = PacketPropertiesLoader.getInstance().getIpV6TrafficClassClass();
    return newTrafficClass(value, clazz);
  }

  /**
   *
   * @param value
   * @param clazz
   * @return
   */
  public IpV6TrafficClass newTrafficClass(
    byte value, Class<? extends IpV6TrafficClass> clazz
  ) {
    if (clazz == null) {
      throw new NullPointerException("clazz may not be null");
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", byte.class);
      return (IpV6TrafficClass)newInstance.invoke(null, value);
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
