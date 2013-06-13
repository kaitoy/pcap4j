/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.TcpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticTcpPortPacketFactory
extends AbstractStaticPacketFactory<TcpPort> {

  private static final StaticTcpPortPacketFactory INSTANCE
    = new StaticTcpPortPacketFactory();

  private StaticTcpPortPacketFactory() {
//    instantiaters.put(
//      TcpPort.HTTP, new PacketInstantiater() {
//        @Override
//        public Packet newInstance(byte[] rawData) {
//          return HttpPacket.newPacket(rawData);
//        }
//      }
//    );
  };

  /**
   *
   * @return the singleton instance of StaticTcpPortPacketFactory.
   */
  public static StaticTcpPortPacketFactory getInstance() {
    return INSTANCE;
  }

}
