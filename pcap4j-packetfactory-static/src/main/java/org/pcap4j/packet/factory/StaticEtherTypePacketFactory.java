/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticEtherTypePacketFactory
extends AbstractStaticPacketFactory<EtherType> {

  private static final StaticEtherTypePacketFactory INSTANCE
    = new StaticEtherTypePacketFactory();

  private StaticEtherTypePacketFactory() {
    instantiaters.put(
      EtherType.IPV4, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV4Packet.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      EtherType.ARP, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return ArpPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      EtherType.DOT1Q_VLAN_TAGGED_FRAMES, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return Dot1qVlanTagPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      EtherType.IPV6, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IpV6Packet.newPacket(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticEtherTypePacketFactory.
   */
  public static StaticEtherTypePacketFactory getInstance() {
    return INSTANCE;
  }

}
