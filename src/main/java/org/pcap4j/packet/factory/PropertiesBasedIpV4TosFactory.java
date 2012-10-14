/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.PacketPropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4TosFactory implements IpV4TosFactory {

  private static final PropertiesBasedIpV4TosFactory INSTANCE
    = new PropertiesBasedIpV4TosFactory();

  private PropertiesBasedIpV4TosFactory() {}

  /**
   *
   * @return
   */
  public static PropertiesBasedIpV4TosFactory getInstance() { return INSTANCE; }

  public IpV4Tos newTos(byte value) {
    Class<? extends IpV4Tos> tosClass
      = PacketPropertiesLoader.getInstance().getIpV4TosClass();
    return newTos(value, tosClass);
  }

  /**
   *
   * @param value
   * @param tosClass
   * @return
   */
  public IpV4Tos newTos(byte value, Class<? extends IpV4Tos> tosClass) {
    if (tosClass == null) {
      throw new NullPointerException("tosClass may not be null");
    }

    try {
      Method newInstance = tosClass.getMethod("newInstance", byte.class);
      return (IpV4Tos)newInstance.invoke(null, value);
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
