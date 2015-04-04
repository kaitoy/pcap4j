/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 * @param <T> target
 * @param <N> number
 */
public interface PacketFactory<T, N extends NamedNumber<?, ?>> {

  /**
   * @param rawData
   * @param offset
   * @param length
   * @param number
   * @return a new data object.
   */
  public T newInstance(byte[] rawData, int offset, int length, N number);

  /**
   * @param rawData
   * @param offset
   * @param length
   * @return a new data object.
   */
  public T newInstance(byte[] rawData, int offset, int length);

  /**
   * @param number
   * @return a {@link java.lang.Class Class} object this factory instantiates
   *         by {@link #newInstance(byte[], NamedNumber)} with the number argument.
   */
  public Class<? extends T> getTargetClass(N number);

  /**
   *
   * @return a {@link java.lang.Class Class} object this factory instantiates
   *         by {@link #newInstance(byte[])}.
   */
  public Class<? extends T> getTargetClass();

}
