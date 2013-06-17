/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
final class SimpleFactoryBinder {

  private static final SimpleFactoryBinder INSTANCE = new SimpleFactoryBinder();

  private SimpleFactoryBinder() {}

  public static SimpleFactoryBinder getInstance() { return INSTANCE; }

  @SuppressWarnings("unchecked")
  public <T, N extends NamedNumber<?>> PacketFactory<T, N> getPacketFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    if (Packet.class.isAssignableFrom(targetClass)) {
      return (PacketFactory<T, N>)StaticUnknownPacketFactory.getInstance();
    } else {
      StringBuilder sb = new StringBuilder(100);
      sb.append("targetClass: ").append(targetClass)
        .append(" numberClass: ").append(numberClass);
      throw new IllegalArgumentException(sb.toString());
    }
  }

}
