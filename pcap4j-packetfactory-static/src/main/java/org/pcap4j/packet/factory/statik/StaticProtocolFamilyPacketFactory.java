/*_##########################################################################
  _##
  _##  Copyright (C) 2015-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ProtocolFamily;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.5.0
 */
public final class StaticProtocolFamilyPacketFactory
    extends AbstractStaticPacketFactory<ProtocolFamily> {

  private static final StaticProtocolFamilyPacketFactory INSTANCE =
      new StaticProtocolFamilyPacketFactory();

  private StaticProtocolFamilyPacketFactory() {
    instantiaters.put(
        ProtocolFamily.PF_INET,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV4Packet.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV4Packet> getTargetClass() {
            return IpV4Packet.class;
          }
        });
    instantiaters.put(
        ProtocolFamily.PF_INET6,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6Packet.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6Packet> getTargetClass() {
            return IpV6Packet.class;
          }
        });
  }

  /** @return the singleton instance of StaticProtocolFamilyPacketFactory. */
  public static StaticProtocolFamilyPacketFactory getInstance() {
    return INSTANCE;
  }
}
