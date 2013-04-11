/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
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
public final class IcmpV4Helper {

  private IcmpV4Helper() { throw new AssertionError(); }

  /**
   *
   * @param packet IPv4 Packet
   * @return
   */
  public static Packet makePacketForInvokingPacketField(Packet packet) {
    if (
         packet == null
      || packet.getPayload() == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("packet: ").append(packet)
        .append(" packet.getPayload(): ").append(packet.getPayload());
      throw new NullPointerException(sb.toString());
    }

    if (packet.getPayload().length() <= 8) {
      return packet;
    }

    int length = 0;
    int prelength = 0;
    int pos = 0;
    Packet last = null;
    for (Packet p: packet.getPayload()) {
      if (p.getHeader() != null) {
        prelength = length;
        length += p.getHeader().length();
        pos++;
        if (length > 8) {
          last = p;
          break;
        }
      }
      else {
        prelength = length;
        length += p.length();
        pos++;
        last = p;
        break;
      }
    }

    Packet.Builder resultBuilder = packet.getBuilder();
    for (Packet.Builder b: resultBuilder) {
      if (b instanceof LengthBuilder) {
        ((LengthBuilder<?>)b).correctLengthAtBuild(false);
      }
      if (b instanceof ChecksumBuilder) {
        ((ChecksumBuilder<?>)b).correctChecksumAtBuild(false);
      }

      pos--;
      if (pos == 0) {
        b.payloadBuilder(
            new UnknownPacket.Builder()
              .rawData(
                 ByteArrays.getSubArray(last.getRawData(), 0, 8 - prelength)
               )
          );
        break;
      }
    }

    return resultBuilder.build();
  }

}
