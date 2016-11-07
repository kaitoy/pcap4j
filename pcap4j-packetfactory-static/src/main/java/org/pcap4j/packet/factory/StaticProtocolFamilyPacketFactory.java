/*_##########################################################################
  _##
  _##  Copyright (C) 2015-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.ProtocolFamily;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.5.0
 */
public final class StaticProtocolFamilyPacketFactory
implements PacketFactory<Packet, ProtocolFamily> {

  private static final StaticProtocolFamilyPacketFactory INSTANCE
    = new StaticProtocolFamilyPacketFactory();

  private StaticProtocolFamilyPacketFactory() {}

  /**
   * @return the singleton instance of StaticProtocolFamilyPacketFactory.
   */
  public static StaticProtocolFamilyPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, ProtocolFamily... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (ProtocolFamily num: numbers) {
        if (num == ProtocolFamily.PF_INET) {
          return IpV4Packet.newPacket(rawData, offset, length);
        }
        else if (num == ProtocolFamily.PF_INET6) {
          return IpV6Packet.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
