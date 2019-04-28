/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticTcpPortPacketFactory extends AbstractStaticPacketFactory<TcpPort> {

  private static final StaticTcpPortPacketFactory INSTANCE = new StaticTcpPortPacketFactory();

  private StaticTcpPortPacketFactory() {
    instantiaters.put(
        TcpPort.DOMAIN,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<DnsPacket> getTargetClass() {
            return DnsPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticTcpPortPacketFactory. */
  public static StaticTcpPortPacketFactory getInstance() {
    return INSTANCE;
  }
}
