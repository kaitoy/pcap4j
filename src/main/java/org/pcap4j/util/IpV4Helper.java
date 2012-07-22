/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.AnonymousPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.PacketFactories;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.Packet;

/**
 * @author Kaito
 * @since pcap4j 0.9.9
 */
public final class IpV4Helper {

  private IpV4Helper() { throw new AssertionError(); }

  /**
   *
   * @param packet
   * @param mtu
   * @return
   */
  public static List<IpV4Packet> fragment(IpV4Packet packet, int mtu) {
    List<IpV4Packet> list = new ArrayList<IpV4Packet>();

    if (packet.length() <= mtu) {
      list.add(packet);
      return list;
    }

    IpV4Header header = packet.getHeader();
    byte[] payload = packet.getPayload().getRawData();
    int max_payload_length = mtu - header.length();
    int actual_max_payload_length
      = max_payload_length % 8 == 0 ? max_payload_length
                                    : max_payload_length - max_payload_length % 8;
    int rest_length = payload.length;
    int srcPos = 0;
    while (rest_length > 0) {
      if (rest_length > max_payload_length) {
        byte[] fragmented_payload = new byte[actual_max_payload_length];
        System.arraycopy(
          payload, srcPos, fragmented_payload, 0, actual_max_payload_length
        );

        IpV4Packet.Builder b = packet.getBuilder();
        b.moreFragmentFlag(true)
         .flagmentOffset((short)(srcPos / 8))
         .payloadBuilder(
            new AnonymousPacket.Builder().rawData(fragmented_payload)
          );
        list.add(b.build());

        rest_length -= fragmented_payload.length;
        srcPos += fragmented_payload.length;
      }
      else {
        byte[] fragmented_payload = new byte[rest_length];
        System.arraycopy(
          payload, srcPos, fragmented_payload, 0, rest_length
        );

        IpV4Packet.Builder b = packet.getBuilder();
        b.moreFragmentFlag(false)
         .flagmentOffset((short)(srcPos / 8))
         .payloadBuilder(
            new AnonymousPacket.Builder().rawData(fragmented_payload)
          );
        list.add(b.build());

        break;
      }
    }

    return list;
  }

  /**
   *
   * @param list
   * @return
   */
  public static IpV4Packet defragment(List<IpV4Packet> list) {
    Collections.sort(
      list,
      new Comparator<IpV4Packet>()  {
        public int compare(IpV4Packet p1, IpV4Packet p2) {
          return p1.getHeader().getFlagmentOffsetAsInt()
                   - p2.getHeader().getFlagmentOffsetAsInt();
        }
      }
    );

    IpV4Header lastPacketHeader = list.get(list.size() - 1).getHeader();
    int payloadLength
      = lastPacketHeader.getFlagmentOffsetAsInt() * 8
          + lastPacketHeader.getTotalLengthAsInt()
          - lastPacketHeader.getIhlAsInt() * 4;
    if (payloadLength <= 0) {
      throw new IllegalArgumentException("Can't defragment: " + list);
    }

    final byte[] defragmentedPayload = new byte[payloadLength];
    int destPos = 0;
    try {
      for (IpV4Packet p: list) {
        byte[] rawPayload = p.getPayload().getRawData();
        System.arraycopy(rawPayload, 0, defragmentedPayload, destPos, rawPayload.length);
        destPos += rawPayload.length;
      }
    } catch (NullPointerException e) {
      throw new IllegalArgumentException("Can't defragment: " + list);
    } catch (ArrayStoreException e) {
      throw new IllegalArgumentException("Can't defragment: " + list);
    } catch (IndexOutOfBoundsException e) {
      throw new IllegalArgumentException("Can't defragment: " + list);
    }

    IpV4Packet.Builder b = list.get(0).getBuilder();
    final IpNumber ipNumber = lastPacketHeader.getProtocol();

    b.moreFragmentFlag(false)
     .flagmentOffset((short)0)
     .payloadBuilder(
        new AbstractBuilder() {
          public Packet build() {
            return PacketFactories.getPacketFactory(IpNumber.class)
                     .newPacket(defragmentedPayload, ipNumber);
          }
        }
      );

    return b.build();
  }

}
