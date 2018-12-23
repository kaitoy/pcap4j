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
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param number number
   * @return a new data object.
   */
  public T newInstance(byte[] rawData, int offset, int length, N number);

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new data object.
   */
  public T newInstance(byte[] rawData, int offset, int length);

  /**
   * @param number number
   * @return a {@link java.lang.Class Class} object this factory instantiates by {@link
   *     #newInstance(byte[], int, int, NamedNumber)} with the number argument.
   */
  public Class<? extends T> getTargetClass(N number);

  /**
   * @return a {@link java.lang.Class Class} object this factory instantiates by {@link
   *     #newInstance(byte[], int, int)}.
   */
  public Class<? extends T> getTargetClass();
}
