/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased.services;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.factory.PacketFactoryBinder;
import org.pcap4j.packet.factory.propertiesbased.PacketFactoryPropertiesLoader;
import org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.8.0
 */
final class PropertiesBasedPacketFactoryBinder implements PacketFactoryBinder {

  private static final PacketFactoryBinder INSTANCE = new PropertiesBasedPacketFactoryBinder();

  private final Map<CacheKey, PacketFactory<?, ?>> cache =
      new ConcurrentHashMap<CacheKey, PacketFactory<?, ?>>();

  private PropertiesBasedPacketFactoryBinder() {}

  public static PacketFactoryBinder getInstance() {
    return INSTANCE;
  }

  @Override
  public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
      Class<T> targetClass, Class<N> numberClass) {
    if (Packet.class.isAssignableFrom(targetClass)) {
      @SuppressWarnings("unchecked")
      PacketFactory<T, N> factory =
          (PacketFactory<T, N>) PropertiesBasedPacketFactory.getInstance();
      return factory;
    }

    CacheKey key = new CacheKey(targetClass, numberClass);

    @SuppressWarnings("unchecked")
    PacketFactory<T, N> cachedFactory = (PacketFactory<T, N>) cache.get(key);
    if (cachedFactory != null) {
      return cachedFactory;
    }

    @SuppressWarnings("unchecked")
    Class<? extends PacketFactory<T, N>> factoryClass =
        (Class<? extends PacketFactory<T, N>>)
            PacketFactoryPropertiesLoader.getInstance()
                .getPacketFactoryClass(targetClass, numberClass);

    try {
      Method getInstance = factoryClass.getMethod("getInstance");

      @SuppressWarnings("unchecked")
      PacketFactory<T, N> factory = (PacketFactory<T, N>) getInstance.invoke(null);
      cache.put(key, factory);
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
      throw new IllegalStateException(e);
    }
  }

  private static final class CacheKey {

    private final Class<?> targetClass;
    private final Class<? extends NamedNumber<?, ?>> numberClass;

    public CacheKey(Class<?> targetClass, Class<? extends NamedNumber<?, ?>> numberClass) {
      this.targetClass = targetClass;
      this.numberClass = numberClass;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }
      CacheKey other = (CacheKey) obj;
      return other.numberClass.equals(this.numberClass)
          && other.targetClass.equals(this.targetClass);
    }

    @Override
    public int hashCode() {
      int result = 17;
      result = 31 * result + targetClass.hashCode();
      result = 31 * result + numberClass.hashCode();
      return result;
    }
  }
}
