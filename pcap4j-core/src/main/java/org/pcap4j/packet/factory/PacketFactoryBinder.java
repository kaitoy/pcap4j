/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * <p>Pcap4J modules can provide a factory to build new packets as they are received.<br>
 * The implementing modules must also provide a {@link PacketFactoryBinderProvider}</p>
 * 
 * @author Jordan Dubie
 * @since pcap4j 1.7.6
 */
public interface PacketFactoryBinder {
    /**
     * Provides a {@link PacketFactory} to build the received packets.
     * 
     * @param targetClass targetClass
     * @param numberClass numberClass
     * @return the factory
     */
    public <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getPacketFactory(Class<T> targetClass, Class<N> numberClass);
}
