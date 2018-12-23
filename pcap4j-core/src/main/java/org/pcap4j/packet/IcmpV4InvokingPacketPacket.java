/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.NotApplicable;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
abstract class IcmpV4InvokingPacketPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -739710899445035385L;

  /*
   *   0                            15                              31
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |IPv4 Header + 64bits of Original Data Datagram(invoking packet)|
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   */
  private final Packet payload;

  /** */
  protected IcmpV4InvokingPacketPacket() {
    this.payload = null;
  }

  /**
   * @param rawData rawData
   * @param payloadOffset payloadOffset
   * @param payloadLength payloadLength
   */
  protected IcmpV4InvokingPacketPacket(byte[] rawData, int payloadOffset, int payloadLength) {
    Packet p =
        PacketFactories.getFactory(Packet.class, EtherType.class)
            .newInstance(rawData, payloadOffset, payloadLength, EtherType.IPV4);

    if (p instanceof IllegalPacket) {
      this.payload = p;
    } else if (p.contains(IllegalPacket.class)) {
      Packet.Builder builder = p.getBuilder();
      byte[] ipRawData = p.get(IllegalPacket.class).getRawData();
      builder
          .getOuterOf(IllegalPacket.Builder.class)
          .payloadBuilder(
              PacketFactories.getFactory(Packet.class, NotApplicable.class)
                  .newInstance(ipRawData, 0, ipRawData.length, NotApplicable.UNKNOWN)
                  .getBuilder());
      for (Packet.Builder b : builder) {
        if (b instanceof LengthBuilder) {
          ((LengthBuilder<?>) b).correctLengthAtBuild(false);
        }
        if (b instanceof ChecksumBuilder) {
          ((ChecksumBuilder<?>) b).correctChecksumAtBuild(false);
        }
      }
      this.payload = builder.build();
    } else {
      this.payload = p;
    }
  }

  /** @param builder builder */
  protected IcmpV4InvokingPacketPacket(Builder builder) {
    if (builder == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payload;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  abstract static class Builder extends AbstractBuilder {

    private Packet payload;

    /** */
    public Builder() {}

    /** @param packet packet */
    protected Builder(IcmpV4InvokingPacketPacket packet) {
      this.payload = packet.payload;
    }

    /**
     * @param payload payload
     * @return this Builder object for method chaining.
     */
    public Builder payload(Packet payload) {
      this.payload = payload;
      return this;
    }
  }
}
