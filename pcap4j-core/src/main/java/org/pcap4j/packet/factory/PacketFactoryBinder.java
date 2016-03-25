/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author anylain
 * @since pcap4j 1.6.3
 */
interface PacketFactoryBinder {

  <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory( Class<T> targetClass, Class<N> numberClass);

}
