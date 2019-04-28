/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.Dot11ProbeRequestPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.Dot11FrameType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class StaticDot11FrameTypePacketFactory
    extends AbstractStaticPacketFactory<Dot11FrameType> {

  private static final StaticDot11FrameTypePacketFactory INSTANCE =
      new StaticDot11FrameTypePacketFactory();

  private StaticDot11FrameTypePacketFactory() {
    instantiaters.put(
        Dot11FrameType.PROBE_REQUEST,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return Dot11ProbeRequestPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<Dot11ProbeRequestPacket> getTargetClass() {
            return Dot11ProbeRequestPacket.class;
          }
        });
  };

  /** @return the singleton instance of StaticDot11FrameTypePacketFactory. */
  public static StaticDot11FrameTypePacketFactory getInstance() {
    return INSTANCE;
  }
}
