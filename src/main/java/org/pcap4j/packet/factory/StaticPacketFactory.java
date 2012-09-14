/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
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
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6ExtDestinationOptionsPacket;
import org.pcap4j.packet.IpV6ExtFragmentPacket;
import org.pcap4j.packet.IpV6ExtHopByHopOptionsPacket;
import org.pcap4j.packet.IpV6ExtRoutingPacket;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class StaticPacketFactory implements PacketFactory {

  private static final StaticPacketFactory INSTANCE
    = new StaticPacketFactory();

  private StaticPacketFactory() {};

  /**
   *
   * @return
   */
  public static StaticPacketFactory getInstance() { return INSTANCE; }

  public Packet newPacket(byte[] rawData, NamedNumber<?> number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      if (number instanceof DataLinkType) {
        if (number.equals(DataLinkType.EN10MB)) {
          return EthernetPacket.newPacket(rawData);
        }
      }
      else if (number instanceof EtherType) {
        if (number.equals(EtherType.IPV4)) {
          return IpV4Packet.newPacket(rawData);
        }
        else if (number.equals(EtherType.IPV6)) {
          return IpV6Packet.newPacket(rawData);
        }
        else if (number.equals(EtherType.ARP)) {
          return ArpPacket.newPacket(rawData);
        }
        else if (number.equals(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)) {
          return Dot1qVlanTagPacket.newPacket(rawData);
        }
      }
      else if (number instanceof IpNumber) {
        if (number.equals(IpNumber.UDP)) {
          return UdpPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.ICMPV4)) {
          return IcmpV4CommonPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.IPV6_HOPOPT)) {
          return IpV6ExtHopByHopOptionsPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.IPV6_FRAG)) {
          return IpV6ExtFragmentPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.IPV6_DST_OPTS)) {
          return IpV6ExtDestinationOptionsPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.IPV6_ROUTE)) {
          return IpV6ExtRoutingPacket.newPacket(rawData);
        }
        else if (number.equals(IpNumber.IPV6_NONXT)) {
          return UnknownPacket.newPacket(rawData);
        }
      }
      else if (number instanceof IcmpV4Type) {
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
      }
//      else if (number instanceof UdpPort) {
//
//      }
    } catch (IllegalRawDataException e) {
      return IllegalPacket.newPacket(rawData);
    }

    return UnknownPacket.newPacket(rawData);
  }

  public Packet newPacket(byte[] rawData) {
    return UnknownPacket.newPacket(rawData);
  }

}
