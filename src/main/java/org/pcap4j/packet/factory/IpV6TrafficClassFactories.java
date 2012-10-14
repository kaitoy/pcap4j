/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.PacketPropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV6TrafficClassFactories {

  private static volatile IpV6TrafficClassFactory cache;

  private IpV6TrafficClassFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return
   */
  public static IpV6TrafficClassFactory getFactory() {
    IpV6TrafficClassFactory cachedFactory = cache;
    if (cachedFactory != null) {
      return cachedFactory;
    }

    Class<? extends IpV6TrafficClassFactory> factoryClass
      = (Class<? extends IpV6TrafficClassFactory>)PacketPropertiesLoader
          .getInstance().getIpV6TrafficClassFactoryClass();
    try {
      Method getInstance = factoryClass.getMethod("getInstance");
      cache = (IpV6TrafficClassFactory)getInstance.invoke(null);
      return cache;
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

  /**
   *
   */
  public static void clearCache() {
    cache = null;
  }

}
