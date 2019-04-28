/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticEtherTypePacketFactory extends AbstractStaticPacketFactory<EtherType> {

  private static final StaticEtherTypePacketFactory INSTANCE = new StaticEtherTypePacketFactory();

  private StaticEtherTypePacketFactory() {
    instantiaters.put(
        EtherType.IPV4,
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
        EtherType.ARP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return ArpPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<ArpPacket> getTargetClass() {
            return ArpPacket.class;
          }
        });
    instantiaters.put(
        EtherType.DOT1Q_VLAN_TAGGED_FRAMES,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return Dot1qVlanTagPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<Dot1qVlanTagPacket> getTargetClass() {
            return Dot1qVlanTagPacket.class;
          }
        });
    instantiaters.put(
        EtherType.IPV6,
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

  /** @return the singleton instance of StaticEtherTypePacketFactory. */
  public static StaticEtherTypePacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, EtherType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    PacketInstantiater instantiater = instantiaters.get(number);
    if (instantiater != null) {
      try {
        return instantiater.newInstance(rawData, offset, length);
      } catch (IllegalRawDataException e) {
        return IllegalPacket.newPacket(rawData, offset, length);
      }
    }

    if ((number.value() & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
      try {
        return LlcPacket.newPacket(rawData, offset, length);
      } catch (IllegalRawDataException e) {
        IllegalPacket.newPacket(rawData, offset, length);
      }
    }

    return newInstance(rawData, offset, length);
  }
}
