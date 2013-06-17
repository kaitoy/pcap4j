/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
final class FactoryBinder {

  private static final FactoryBinder INSTANCE = new FactoryBinder();

  private FactoryBinder() {}

  public static FactoryBinder getInstance() { return INSTANCE; }

  public <T, N extends NamedNumber<?>> PacketFactory<T, N> getPacketFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    throw new UnsupportedOperationException("This code is never included in pcap4j-core.jar.");
  }

}
