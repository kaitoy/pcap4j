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
final class SimpleFactoryBinder {

  private static final SimpleFactoryBinder INSTANCE = new SimpleFactoryBinder();

  private SimpleFactoryBinder() {}

  public static SimpleFactoryBinder getInstance() { return INSTANCE; }

  public PacketFactory<NamedNumber<?>> getFactory(
    Class<? extends NamedNumber<?>> numberClass
  ) {
    return StaticUnknownPacketFactory.getInstance();
  }

  public <T, N extends NamedNumber<?>> ClassifiedDataFactory<T, N>
  getFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    throw new UnsupportedOperationException("This should be never used.");
  }

}
