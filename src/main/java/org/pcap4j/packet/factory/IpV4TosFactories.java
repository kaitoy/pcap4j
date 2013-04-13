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
public final class IpV4TosFactories {

  private static volatile IpV4TosFactory cache;

  private IpV4TosFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return IpV4TosFactory
   */
  public static IpV4TosFactory getFactory() {
    IpV4TosFactory cachedFactory = cache;
    if (cachedFactory != null) {
      return cachedFactory;
    }

    Class<? extends IpV4TosFactory> factoryClass
      = (Class<? extends IpV4TosFactory>)PacketPropertiesLoader.getInstance()
          .getIpV4TosFactoryClass();
    try {
      Method getInstance = factoryClass.getMethod("getInstance");
      cache = (IpV4TosFactory)getInstance.invoke(null);
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
