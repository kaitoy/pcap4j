/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.GtpSelector;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
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
    instantiaters.put(
      UdpPort.GTP_C, new PacketInstantiater() {
        @Override
        public Packet newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return GtpSelector.newPacket(rawData, offset, length);
        }
        @Override
        public Class<GtpSelector> getTargetClass() {
          return GtpSelector.class;
        }
      }
    );
    instantiaters.put(
      UdpPort.GTP_U, new PacketInstantiater() {
        @Override
        public Packet newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return GtpSelector.newPacket(rawData, offset, length);
        }
        @Override
        public Class<GtpSelector> getTargetClass() {
          return GtpSelector.class;
        }
      }
    );
    instantiaters.put(
      UdpPort.GTP_PRIME, new PacketInstantiater() {
        @Override
        public Packet newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return GtpSelector.newPacket(rawData, offset, length);
        }
        @Override
        public Class<GtpSelector> getTargetClass() {
          return GtpSelector.class;
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticUdpPortPacketFactory.
   */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }

}
