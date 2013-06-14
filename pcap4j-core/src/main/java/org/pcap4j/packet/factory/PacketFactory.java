/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
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
public interface PacketFactory<T, N extends NamedNumber<?>> {

  /**
   *
   * @param rawData
   * @param number
   * @return a new data object.
   */
  public T newInstance(byte[] rawData, N number);

  /**
   *
   * @param rawData
   * @return a new data object.
   */
  public T newInstance(byte[] rawData);

}
