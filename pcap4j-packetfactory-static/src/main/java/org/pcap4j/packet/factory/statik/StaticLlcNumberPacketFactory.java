/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SnapPacket;
import org.pcap4j.packet.namednumber.LlcNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class StaticLlcNumberPacketFactory extends AbstractStaticPacketFactory<LlcNumber> {

  private static final StaticLlcNumberPacketFactory INSTANCE = new StaticLlcNumberPacketFactory();

  private StaticLlcNumberPacketFactory() {
    instantiaters.put(
        LlcNumber.ARP,
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
        LlcNumber.SNAP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return SnapPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<SnapPacket> getTargetClass() {
            return SnapPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticLlcNumberPacketFactory. */
  public static StaticLlcNumberPacketFactory getInstance() {
    return INSTANCE;
  }
}
