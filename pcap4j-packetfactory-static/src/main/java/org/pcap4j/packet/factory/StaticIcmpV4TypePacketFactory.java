/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4InformationReplyPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIcmpV4TypePacketFactory implements PacketFactory<Packet, IcmpV4Type> {

  private static final StaticIcmpV4TypePacketFactory INSTANCE
    = new StaticIcmpV4TypePacketFactory();

  private StaticIcmpV4TypePacketFactory() {}

  /**
   * @return the singleton instance of StaticIcmpV4TypePacketFactory.
   */
  public static StaticIcmpV4TypePacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, IcmpV4Type... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (IcmpV4Type num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IcmpV4EchoReplyPacket.newPacket(rawData, offset, length);
          case 3:
            return IcmpV4DestinationUnreachablePacket.newPacket(rawData, offset, length);
          case 4:
            return IcmpV4SourceQuenchPacket.newPacket(rawData, offset, length);
          case 5:
            return IcmpV4RedirectPacket.newPacket(rawData, offset, length);
          case 8:
            return IcmpV4EchoPacket.newPacket(rawData, offset, length);
          case 11:
            return IcmpV4TimeExceededPacket.newPacket(rawData, offset, length);
          case 12:
            return IcmpV4ParameterProblemPacket.newPacket(rawData, offset, length);
          case 13:
            return IcmpV4TimestampPacket.newPacket(rawData, offset, length);
          case 14:
            return IcmpV4TimestampReplyPacket.newPacket(rawData, offset, length);
          case 15:
            return IcmpV4InformationRequestPacket.newPacket(rawData, offset, length);
          case 16:
            return IcmpV4InformationReplyPacket.newPacket(rawData, offset, length);
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
