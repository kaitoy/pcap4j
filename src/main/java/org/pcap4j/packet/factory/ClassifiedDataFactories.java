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
 * @since pcap4j 0.9.11
 */
public final class ClassifiedDataFactories {

  private static final
  Map<CacheKey, ClassifiedDataFactory<?, ?>> cache
    = new ConcurrentHashMap<CacheKey, ClassifiedDataFactory<?, ?>>();

  private ClassifiedDataFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return
   */
  public static <T, N extends NamedNumber<?>> ClassifiedDataFactory<T, N>
  getFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    if (numberClass == null) {
      throw new NullPointerException("numberClass: " + numberClass);
    }

    CacheKey key = new CacheKey(targetClass, numberClass);

    @SuppressWarnings("unchecked")
    ClassifiedDataFactory<T, N> cachedFactory
      = (ClassifiedDataFactory<T, N>)cache.get(key);
    if (cachedFactory != null) {
      return cachedFactory;
    }

    @SuppressWarnings("unchecked")
    Class<? extends ClassifiedDataFactory<T, N>> factoryClass
      = (Class<? extends ClassifiedDataFactory<T, N>>)PacketPropertiesLoader
          .getInstance()
            .getClassifiedDataFactoryClass(targetClass, numberClass);

    try {
      Method getInstance = factoryClass.getMethod("getInstance");

      @SuppressWarnings("unchecked")
      ClassifiedDataFactory<T, N> factory
        = (ClassifiedDataFactory<T, N>)getInstance.invoke(null);
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

  /**
   *
   */
  public static void clearCache() {
    cache.clear();
  }

  private static final class CacheKey {

    private final  Class<?> targetClass;
    private final Class<? extends NamedNumber<?>> numberClass;

    public CacheKey(
      Class<?> targetClass, Class<? extends NamedNumber<?>> numberClass
    ) {
      this.targetClass = targetClass;
      this.numberClass = numberClass;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }
      CacheKey other = (CacheKey)obj;
      return    other.numberClass.equals(this.numberClass)
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
