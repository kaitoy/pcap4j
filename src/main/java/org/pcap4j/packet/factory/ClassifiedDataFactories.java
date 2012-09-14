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
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class ClassifiedDataFactories {

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

    @SuppressWarnings("unchecked")
    Class<? extends ClassifiedDataFactory<T, N>> factoryClass
      = (Class<? extends ClassifiedDataFactory<T, N>>)PacketPropertiesLoader.getInstance()
          .getClassifiedDataFactoryClass(targetClass, numberClass);

    try {
      Method getInstance = factoryClass.getMethod("getInstance");

      @SuppressWarnings("unchecked")
      ClassifiedDataFactory<T, N> factory = (ClassifiedDataFactory<T, N>)getInstance.invoke(null);
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

}
