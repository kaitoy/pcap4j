/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.util.Comparator;
import java.util.List;
import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpNumber;

public final class IpV6Helper {
  private static final Comparator<IpV6Packet> comparator = new ComparatorImpl();

  private IpV6Helper() {}

  /**
   * @param ipV6Packet fragmented ivp6 packet
   * @return payload length of the fragmented packet
   */
  private static int computePayloadLength(IpV6Packet ipV6Packet) {
    return ipV6Packet.getHeader().getPayloadLength() - computeExtHeaderSizes(ipV6Packet);
  }

  private static int computeExtHeaderSizes(Packet packet) {
    Packet payload = packet.getPayload();
    if (payload instanceof IpV6ExtOptionsPacket) {
      IpV6ExtOptionsPacket ipV6ExtOptionsPacket = (IpV6ExtOptionsPacket) payload;
      return ((ipV6ExtOptionsPacket.getHeader().getHdrExtLenAsInt() + 1) * 8)
          + computeExtHeaderSizes(payload);
    } else if (payload instanceof IpV6ExtFragmentPacket) {
      IpV6ExtFragmentPacket ipV6ExtFragmentPacket = (IpV6ExtFragmentPacket) payload;
      return (ipV6ExtFragmentPacket.getHeader().length());
    } else if (payload instanceof IpV6ExtRoutingPacket) {
      IpV6ExtRoutingPacket ipV6ExtRoutingPacket = (IpV6ExtRoutingPacket) payload;
      return ((ipV6ExtRoutingPacket.getHeader().getHdrExtLenAsInt() + 1) * 8)
          + computeExtHeaderSizes(payload);
    } else {
      throw new IllegalArgumentException("Can't find IpV6 fragment packet: " + packet);
    }
  }

  /**
   * @param outerOfFragment builder of packet which is previous for ext. fragment header
   * @param ipNumber new ip number for the packet
   */
  private static void fixIpNumber(Packet.Builder outerOfFragment, IpNumber ipNumber) {
    if (outerOfFragment instanceof IpV6Packet.Builder) {
      IpV6Packet.Builder builder = (IpV6Packet.Builder) outerOfFragment;
      builder.nextHeader(ipNumber);
    } else if (outerOfFragment instanceof IpV6ExtOptionsPacket.Builder) {
      IpV6ExtOptionsPacket.Builder builder = (IpV6ExtOptionsPacket.Builder) outerOfFragment;
      builder.nextHeader(ipNumber);
    } else if (outerOfFragment instanceof IpV6ExtRoutingPacket.Builder) {
      IpV6ExtRoutingPacket.Builder builder = (IpV6ExtRoutingPacket.Builder) outerOfFragment;
      builder.nextHeader(ipNumber);
    } else {
      throw new IllegalArgumentException("Can't defragment, unexpected header: " + outerOfFragment);
    }
  }

  /**
   * @param list list
   * @return a defragmented packet.
   */
  public static IpV6Packet defragment(List<IpV6Packet> list) {
    list.sort(comparator);
    IpV6Packet lastPacket = list.get(list.size() - 1);
    IpV6ExtFragmentPacket ipV6LastFragmentPacket = lastPacket.get(IpV6ExtFragmentPacket.class);

    int payloadTotalLength =
        ipV6LastFragmentPacket.getHeader().getFragmentOffset() * 8
            + computePayloadLength(lastPacket);

    if (payloadTotalLength <= 0) {
      throw new IllegalArgumentException("Can't defragment: " + list);
    }

    final byte[] defragmentedPayload = new byte[payloadTotalLength];
    int destPos = 0;
    try {
      for (IpV6Packet p : list) {
        IpV6ExtFragmentPacket fragmentPacket = p.get(IpV6ExtFragmentPacket.class);
        byte[] rawPayload = fragmentPacket.getPayload().getRawData();
        System.arraycopy(rawPayload, 0, defragmentedPayload, destPos, rawPayload.length);
        destPos += rawPayload.length;
      }
    } catch (Throwable e) {
      throw new IllegalArgumentException("Can't defragment: " + list, e);
    }

    IpV6Packet firstPacket = list.get(0);
    IpV6ExtFragmentPacket ipV6FirstFragmentPacket = firstPacket.get(IpV6ExtFragmentPacket.class);
    IpV6Packet.Builder builder = firstPacket.getBuilder();
    Packet.Builder outerOfFragmentb = builder.getOuterOf(IpV6ExtFragmentPacket.Builder.class);
    outerOfFragmentb.payloadBuilder(
        new SimpleBuilder(
            PacketFactories.getFactory(Packet.class, IpNumber.class)
                .newInstance(
                    defragmentedPayload,
                    0,
                    defragmentedPayload.length,
                    ipV6FirstFragmentPacket.getHeader().getNextHeader())));
    fixIpNumber(outerOfFragmentb, ipV6FirstFragmentPacket.getHeader().getNextHeader());
    builder.correctLengthAtBuild(true);
    return builder.build();
  }

  private static final class ComparatorImpl implements Comparator<IpV6Packet> {

    @Override
    public int compare(IpV6Packet p1, IpV6Packet p2) {
      IpV6ExtFragmentPacket fp1 = p1.get(IpV6ExtFragmentPacket.class);
      IpV6ExtFragmentPacket fp2 = p2.get(IpV6ExtFragmentPacket.class);

      if (fp1 == null) {
        throw new IllegalArgumentException("Can't defragment: " + p1);
      }

      if (fp2 == null) {
        throw new IllegalArgumentException("Can't defragment: " + p2);
      }

      return fp1.getHeader().getFragmentOffset() - fp2.getHeader().getFragmentOffset();
    }
  }
}
