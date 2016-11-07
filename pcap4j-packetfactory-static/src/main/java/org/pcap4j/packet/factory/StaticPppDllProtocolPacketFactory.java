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
import org.pcap4j.packet.namednumber.PppDllProtocol;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class StaticPppDllProtocolPacketFactory
implements PacketFactory<Packet, PppDllProtocol> {

  private static final StaticPppDllProtocolPacketFactory INSTANCE
    = new StaticPppDllProtocolPacketFactory();

  private StaticPppDllProtocolPacketFactory() {}

  /**
   * @return the singleton instance of StaticPppDllProtocolPacketFactory.
   */
  public static StaticPppDllProtocolPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, PppDllProtocol... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (PppDllProtocol num: numbers) {
        switch (Short.toUnsignedInt(num.value())) {
          case 0x0021:
            return IpV4Packet.newPacket(rawData, offset, length);
          case 0x0057:
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
