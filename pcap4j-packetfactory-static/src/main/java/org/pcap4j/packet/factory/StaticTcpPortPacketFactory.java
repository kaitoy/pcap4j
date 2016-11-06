/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticTcpPortPacketFactory implements PacketFactory<Packet, TcpPort> {

  private static final StaticTcpPortPacketFactory INSTANCE = new StaticTcpPortPacketFactory();

  private StaticTcpPortPacketFactory() {}

  /**
   *
   * @return the singleton instance of StaticTcpPortPacketFactory.
   */
  public static StaticTcpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, TcpPort... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    return UnknownPacket.newPacket(rawData, offset, length);
//    try {
//      for (TcpPort num: numbers) {
//        switch (Short.toUnsignedInt(num.value())) {
//          case 80:
//            return HttpPacket.newPacket(rawData, offset, length);
//        }
//      }
//      return UnknownPacket.newPacket(rawData, offset, length);
//    } catch (IllegalRawDataException e) {
//      return IllegalPacket.newPacket(rawData, offset, length);
//    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
