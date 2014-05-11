/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
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
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return EthernetPacket.newPacket(rawData);
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
