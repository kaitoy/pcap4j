/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticUdpPortPacketFactory
extends AbstractStaticPacketFactory<UdpPort> {

  private static final StaticUdpPortPacketFactory INSTANCE
    = new StaticUdpPortPacketFactory();

  private StaticUdpPortPacketFactory() {
//    instantiaters.put(
//      UdpPort.SNMP, new PacketInstantiater() {
//        @Override
//        public Packet newInstance(
//          byte[] rawData, int offset, int length
//        ) throws IllegalRawDataException {
//          return SnmpPacket.newPacket(rawData, offset, length);
//        }
//        @Override
//        public Class<SnmpPacket> getTargetClass() {
//          return SnmpPacket.class;
//        }
//      }
//    );
  };

  /**
   *
   * @return the singleton instance of StaticUdpPortPacketFactory.
   */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }

}
