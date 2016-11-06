/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * Skeletal implementation of {@link PacketFactory}.
 *
 * @author Kaito Yamada
 * @param <T> target
 * @param <N> number
 * @since pcap4j 2.0.0
 */
public abstract class AbstractPropertiesBasedFactory<T, N extends NamedNumber<?, ?>>
implements PacketFactory<T, N> {

  @SuppressWarnings("unchecked") // instead of @SafeVarargs which can use only for final method.
  @Override
  public T newInstance(
    byte[] rawData, int offset, int length, N... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    Class<? extends T> unknown = getUnknownClass();
    if (unknown == null) {
      throw new NullPointerException("getUnknownClass() returned null.");
    }

    for (N num: numbers) {
      Class<? extends T> target = getTargetClass(num);
      if (target != unknown) {
        return newInstance(rawData, offset, length, target);
      }
    }
    return newInstance(rawData, offset, length, unknown);
  }

  private T newInstance(
    byte[] rawData, int offset, int length, Class<? extends T> target
  ) {
    if (target == null) {
      throw new NullPointerException("target is null");
    }

    try {
      Method factoryMethod
        = target.getMethod(getStaticFactoryMethodName(), byte[].class, int.class, int.class);
      @SuppressWarnings("unchecked")
      T instance = (T) factoryMethod.invoke(null, rawData, offset, length);
      return instance;
    } catch (
        SecurityException
      | NoSuchMethodException
      | IllegalArgumentException
      | IllegalAccessException e
    ) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      if (e.getTargetException() instanceof IllegalRawDataException) {
        return newIllegalData(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param number number
   * @return the class that is supposed to be instantiated for the given number.
   */
  protected abstract Class<? extends T> getTargetClass(N number);

  /**
   * @return the class that is supposed to be instantiated for numbers this factory doesn't support.
   */
  protected abstract Class<? extends T> getUnknownClass();

  /**
   * @return the name of the static factory method to instantiate classes
   *         {@link #getTargetClass getTargetClass(N)} and {@link #getUnknownClass()} return.
   */
  protected abstract String getStaticFactoryMethodName();

  /**
   * This method is called when {@link IllegalRawDataException} is thrown during instantiating
   * a class {@link #getTargetClass getTargetClass(N)} or {@link #getUnknownClass()} return and
   * create an object representing an illegal packet or packet field.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new object.
   */
  protected abstract T newIllegalData(byte[] rawData, int offset, int length);

}
