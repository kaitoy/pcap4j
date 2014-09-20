/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticDataLinkTypePacketFactory
extends AbstractStaticPacketFactory<DataLinkType> {

  private static final StaticDataLinkTypePacketFactory INSTANCE
    = new StaticDataLinkTypePacketFactory();

  private StaticDataLinkTypePacketFactory() {
    instantiaters.put(
      DataLinkType.EN10MB, new PacketInstantiater() {
        @Override
        public Packet newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return EthernetPacket.newPacket(rawData, offset, length);
        }
        @Override
        public Class<EthernetPacket> getTargetClass() {
          return EthernetPacket.class;
        }
      }
    );
    instantiaters.put(
      DataLinkType.RAW, new PacketInstantiater() {
        @Override
        public Packet newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          if (length > 0) {
            int ipVersion = (rawData[0] >> 4) & 0x0f;
            if (ipVersion == 4) {
              return IpV4Packet.newPacket(rawData, offset, length);
            }
            if (ipVersion == 6) {
              return IpV6Packet.newPacket(rawData, offset, length);
            }
          }
          return UnknownPacket.newPacket(rawData, offset, length);
        }
        @Override
        public Class<UnknownPacket> getTargetClass() {
          return UnknownPacket.class;
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticDataLinkTypePacketFactory.
   */
  public static StaticDataLinkTypePacketFactory getInstance() {
    return INSTANCE;
  }

}
