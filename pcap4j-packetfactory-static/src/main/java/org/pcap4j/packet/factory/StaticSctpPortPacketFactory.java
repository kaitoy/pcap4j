/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.SctpPort;

/**
 * @author Jeff Myers
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class StaticSctpPortPacketFactory implements PacketFactory<Packet, SctpPort> {

  private static final StaticSctpPortPacketFactory INSTANCE
    = new StaticSctpPortPacketFactory();

  private StaticSctpPortPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticSctpPortPacketFactory.
   */
  public static StaticSctpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, SctpPort... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    return UnknownPacket.newPacket(rawData, offset, length);
//    try {
//      for (SctpPort num: numbers) {
//        switch (Short.toUnsignedInt(num.value())) {
//          case 80:
//            return HttpPacket.newPacket(rawData, offset, length);
//        }
//      }
//      return UnknownPacket.newPacket(rawData, offset, length);
//    } catch (IllegalRawDataException e) {
//      return IllegalPacket.newPacket(rawData, offset, length, e);
//    }
  }

}
