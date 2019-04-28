/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Ssh2KexInitPacket;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class StaticSsh2MessageNumberPacketFactory
    extends AbstractStaticPacketFactory<Ssh2MessageNumber> {

  private static final StaticSsh2MessageNumberPacketFactory INSTANCE =
      new StaticSsh2MessageNumberPacketFactory();

  private StaticSsh2MessageNumberPacketFactory() {
    instantiaters.put(
        Ssh2MessageNumber.SSH_MSG_KEXINIT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return Ssh2KexInitPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<Ssh2KexInitPacket> getTargetClass() {
            return Ssh2KexInitPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticSsh2MessageNumberPacketFactory. */
  public static StaticSsh2MessageNumberPacketFactory getInstance() {
    return INSTANCE;
  }
}
