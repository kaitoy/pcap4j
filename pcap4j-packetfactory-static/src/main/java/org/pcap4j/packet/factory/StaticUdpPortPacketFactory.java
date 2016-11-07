/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.GtpSelector;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticUdpPortPacketFactory implements PacketFactory<Packet, UdpPort> {

  private static final StaticUdpPortPacketFactory INSTANCE = new StaticUdpPortPacketFactory();

  private StaticUdpPortPacketFactory() {}

  /**
   *
   * @return the singleton instance of StaticUdpPortPacketFactory.
   */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, UdpPort... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (UdpPort num: numbers) {
        switch (Short.toUnsignedInt(num.value())) {
          case 2123:
            return GtpSelector.newPacket(rawData, offset, length);
          case 2152:
            return GtpSelector.newPacket(rawData, offset, length);
          case 3386:
            return GtpSelector.newPacket(rawData, offset, length);
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
