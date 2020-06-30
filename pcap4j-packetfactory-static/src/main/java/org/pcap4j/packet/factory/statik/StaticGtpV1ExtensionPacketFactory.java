/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.GtpV1ExtNRUPacket;
import org.pcap4j.packet.GtpV1ExtPduSessionContainerPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;

/**
 * @author Leo Ma
 * @since pcap4j 1.8.3
 */
public final class StaticGtpV1ExtensionPacketFactory
    extends AbstractStaticPacketFactory<GtpV1ExtensionHeaderType> {

  private static final StaticGtpV1ExtensionPacketFactory INSTANCE =
      new StaticGtpV1ExtensionPacketFactory();

  private StaticGtpV1ExtensionPacketFactory() {
    instantiaters.put(
        GtpV1ExtensionHeaderType.PDU_SESSION_CONTAINER,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return GtpV1ExtPduSessionContainerPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<GtpV1ExtPduSessionContainerPacket> getTargetClass() {
            return GtpV1ExtPduSessionContainerPacket.class;
          }
        });

    instantiaters.put(
            GtpV1ExtensionHeaderType.NR_RAN_CONTAINER, new PacketInstantiater() {
                @Override
                public Packet newInstance(byte[] rawData, int offset, int length) throws IllegalRawDataException {
                    return  GtpV1ExtNRUPacket.newPacket(rawData, offset, length);
                }

                @Override
                public Class<GtpV1ExtNRUPacket> getTargetClass() {
                    return GtpV1ExtNRUPacket.class;
                }
            }
    );
  }

  /** @return the singleton instance of StaticGtpV1ExtensionPacketFactory. */
  public static StaticGtpV1ExtensionPacketFactory getInstance() {
    return INSTANCE;
  }
}
