/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import org.pcap4j.packet.ChecksumBuilder;
import org.pcap4j.packet.LengthBuilder;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV6Helper {

  private IcmpV6Helper() {
    throw new AssertionError();
  }

  /**
   * @param packet an IPv6 Packet
   * @param size the target size in bytes. (i.e. MTU - &lt;IPv6 header(s) size&gt; - &lt;ICMPv6
   *     header size&gt;)
   * @return a new IPv6 packet object.
   */
  public static Packet makePacketForInvokingPacketField(Packet packet, int size) {
    if (packet == null || packet.getHeader() == null || packet.getPayload() == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("packet: ")
          .append(packet)
          .append(" packet.getHeader(): ")
          .append(packet.getHeader())
          .append(" packet.getPayload(): ")
          .append(packet.getPayload());
      throw new NullPointerException(sb.toString());
    }

    if (packet.length() <= size) {
      return packet;
    }

    int length = packet.getHeader().length();
    int prelength = length;
    int pos = 0;
    Packet last = null;
    for (Packet p : packet.getPayload()) {
      if (p.getHeader() != null) {
        prelength = length;
        length += p.getHeader().length();
        pos++;
        if (length > size) {
          last = p;
          break;
        }
      } else {
        prelength = length;
        length += p.length();
        pos++;
        last = p;
        break;
      }
    }

    Packet.Builder resultBuilder = packet.getBuilder();
    for (Packet.Builder b : resultBuilder) {
      if (b instanceof LengthBuilder) {
        ((LengthBuilder<?>) b).correctLengthAtBuild(false);
      }
      if (b instanceof ChecksumBuilder) {
        ((ChecksumBuilder<?>) b).correctChecksumAtBuild(false);
      }

      pos--;
      if (pos == 0) {
        if (size - prelength > 0) {
          b.payloadBuilder(
              new UnknownPacket.Builder()
                  .rawData(ByteArrays.getSubArray(last.getRawData(), 0, size - prelength)));
        } else {
          b.payloadBuilder(null);
        }
        break;
      }
    }

    return resultBuilder.build();
  }

  /**
   * @param packet an IPv6 Packet
   * @param size the target size in bytes. (i.e. MTU - &lt;IPv6 header(s) size&gt; - &lt;ICMPv6
   *     header size&gt; - &lt;IPv6 ND option(s) size&gt;)
   * @return a new IPv6 packet object.
   */
  public static Packet makePacketForRedirectHeaderOption(Packet packet, int size) {
    if (packet.length() > size) {
      return makePacketForInvokingPacketField(packet, size - size % 8);
    } else {
      int length = packet.length();
      return makePacketForInvokingPacketField(packet, length - length % 8);
    }
  }
}
