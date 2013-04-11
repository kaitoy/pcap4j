/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.pcap4j.packet.PacketPropertiesLoader;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class PacketFactories {

  private static final
  Map<Class<? extends NamedNumber<?>>, PacketFactory<?>> cache
    = new ConcurrentHashMap<Class<? extends NamedNumber<?>>, PacketFactory<?>>();

  private PacketFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return
   */
  public static PacketFactory<NamedNumber<?>> getFactory(
    Class<? extends NamedNumber<?>> numberClass
  ) {
    if (numberClass == null) {
      throw new NullPointerException("numberClass: " + numberClass);
    }

    @SuppressWarnings("unchecked")
    PacketFactory<NamedNumber<?>> cachedFactory
      = (PacketFactory<NamedNumber<?>>)cache.get(numberClass);
    if (cachedFactory != null) {
      return cachedFactory;
    }

    Class<? extends PacketFactory<NamedNumber<?>>> factoryClass
      = PacketPropertiesLoader.getInstance().getPacketFactoryClass(numberClass);

    try {
      Method getInstance = factoryClass.getMethod("getInstance");
      @SuppressWarnings("unchecked")
      PacketFactory<NamedNumber<?>> factory
        = (PacketFactory<NamedNumber<?>>)getInstance.invoke(null);
      cache.put(numberClass, factory);
      return factory;
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
    } catch (ClassCastException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   *
   */
  public static void clearCache() {
    cache.clear();
  }

}
