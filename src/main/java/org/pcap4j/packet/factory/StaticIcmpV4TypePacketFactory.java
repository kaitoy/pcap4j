/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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
public final class StaticIcmpV4TypePacketFactory
implements PacketFactory<IcmpV4Type> {

  private static final StaticIcmpV4TypePacketFactory INSTANCE
    = new StaticIcmpV4TypePacketFactory();

  private StaticIcmpV4TypePacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticIcmpV4TypePacketFactory.
   */
  public static StaticIcmpV4TypePacketFactory getInstance() {
    return INSTANCE;
  }

  public Packet newPacket(byte[] rawData, IcmpV4Type number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number.equals(IcmpV4Type.ECHO)) {
        return IcmpV4EchoPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.ECHO_REPLY)) {
        return IcmpV4EchoReplyPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.DESTINATION_UNREACHABLE)) {
        return IcmpV4DestinationUnreachablePacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.TIME_EXCEEDED)) {
        return IcmpV4TimeExceededPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
        return IcmpV4ParameterProblemPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.REDIRECT)) {
        return IcmpV4RedirectPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.SOURCE_QUENCH)) {
        return IcmpV4SourceQuenchPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.INFORMATION_REQUEST)) {
        return IcmpV4InformationRequestPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.INFORMATION_REPLY)) {
        return IcmpV4InformationReplyPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.TIMESTAMP)) {
        return IcmpV4TimestampPacket.newPacket(rawData);
      }
      else if (number.equals(IcmpV4Type.TIMESTAMP_REPLY)) {
        return IcmpV4TimestampReplyPacket.newPacket(rawData);
      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

}
