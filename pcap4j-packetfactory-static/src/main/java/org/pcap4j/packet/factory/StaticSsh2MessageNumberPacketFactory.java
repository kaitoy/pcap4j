/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.Ssh2KexInitPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class StaticSsh2MessageNumberPacketFactory
implements PacketFactory<Packet, Ssh2MessageNumber> {

  private static final StaticSsh2MessageNumberPacketFactory INSTANCE
    = new StaticSsh2MessageNumberPacketFactory();

  private StaticSsh2MessageNumberPacketFactory() {}

  /**
   *
   * @return the singleton instance of StaticSsh2MessageNumberPacketFactory.
   */
  public static StaticSsh2MessageNumberPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, Ssh2MessageNumber... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (Ssh2MessageNumber num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 20:
            return Ssh2KexInitPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
