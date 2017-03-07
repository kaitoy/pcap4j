/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IcmpV6DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV6EchoReplyPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IcmpV6NeighborAdvertisementPacket;
import org.pcap4j.packet.IcmpV6NeighborSolicitationPacket;
import org.pcap4j.packet.IcmpV6PacketTooBigPacket;
import org.pcap4j.packet.IcmpV6ParameterProblemPacket;
import org.pcap4j.packet.IcmpV6RedirectPacket;
import org.pcap4j.packet.IcmpV6RouterAdvertisementPacket;
import org.pcap4j.packet.IcmpV6RouterSolicitationPacket;
import org.pcap4j.packet.IcmpV6TimeExceededPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IcmpV6Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticIcmpV6TypePacketFactory implements PacketFactory<Packet, IcmpV6Type> {

  private static final StaticIcmpV6TypePacketFactory INSTANCE
    = new StaticIcmpV6TypePacketFactory();

  private StaticIcmpV6TypePacketFactory() {}

  /**
   * @return the singleton instance of StaticIcmpV6TypePacketFactory.
   */
  public static StaticIcmpV6TypePacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, IcmpV6Type... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (IcmpV6Type num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 1:
            return IcmpV6DestinationUnreachablePacket.newPacket(rawData, offset, length);
          case 2:
            return IcmpV6PacketTooBigPacket.newPacket(rawData, offset, length);
          case 3:
            return IcmpV6TimeExceededPacket.newPacket(rawData, offset, length);
          case 4:
            return IcmpV6ParameterProblemPacket.newPacket(rawData, offset, length);
          case 128:
            return IcmpV6EchoRequestPacket.newPacket(rawData, offset, length);
          case 129:
            return IcmpV6EchoReplyPacket.newPacket(rawData, offset, length);
          case 133:
            return IcmpV6RouterSolicitationPacket.newPacket(rawData, offset, length);
          case 134:
            return IcmpV6RouterAdvertisementPacket.newPacket(rawData, offset, length);
          case 135:
            return IcmpV6NeighborSolicitationPacket.newPacket(rawData, offset, length);
          case 136:
            return IcmpV6NeighborAdvertisementPacket.newPacket(rawData, offset, length);
          case 137:
            return IcmpV6RedirectPacket.newPacket(rawData, offset, length);
        }
      }
      return UnknownPacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData, offset, length, e);
    }
  }

}
