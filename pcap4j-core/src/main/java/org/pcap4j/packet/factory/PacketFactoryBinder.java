/*_##########################################################################
  _##
  _##  Copyright (C) 2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * Pcap4J modules can provide a factory to build new packets as they are received.<br>
 * The implementing modules must also provide a {@link PacketFactoryBinderProvider}
 *
 * @author Jordan Dubie
 * @since pcap4j 1.8.0
 */
public interface PacketFactoryBinder {
  /**
   * Provides a {@link PacketFactory} to build the received packets.
   *
   * @param targetClass targetClass
   * @param numberClass numberClass
   * @param <T> the type of object the factory method returns.
   * @param <N> the type of object that is given to the factory method.
   * @return the factory
   */
  public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(
      Class<T> targetClass, Class<N> numberClass);
}
