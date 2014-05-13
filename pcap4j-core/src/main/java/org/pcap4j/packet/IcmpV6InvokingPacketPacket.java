/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
abstract class IcmpV6InvokingPacketPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 1169814867596950985L;

  /*
   *   0                            15                              31
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                    As much of invoking packet                 |
   *  +                as possible without the ICMPv6 packet          +
   *  |                exceeding the minimum IPv6 MTU [IPv6]          |
   */
  private final Packet payload;

  /**
   *
   */
  protected IcmpV6InvokingPacketPacket() {
    this.payload = null;
  }

  /**
   *
   * @param rawPayload
   */
  protected IcmpV6InvokingPacketPacket(byte[] rawPayload) {
    if (rawPayload == null) {
      throw new NullPointerException("rawPayload must not be null.");
    }
    if (rawPayload.length == 0) {
      throw new IllegalArgumentException("rawPayload is empty.");
    }

    Packet p = PacketFactories.getFactory(Packet.class, EtherType.class)
                 .newInstance(rawPayload, EtherType.IPV6);

    if (p instanceof IllegalPacket) {
      this.payload = p;
      return;
    }
    else if (p.contains(IllegalPacket.class)) {
      Packet.Builder builder = p.getBuilder();
      builder.getOuterOf(IllegalPacket.Builder.class)
                .payloadBuilder(
                   new UnknownPacket.Builder()
                     .rawData(p.get(IllegalPacket.class).getRawData())
                 );
      for (Packet.Builder b: builder) {
        if (b instanceof LengthBuilder) {
          ((LengthBuilder<?>)b).correctLengthAtBuild(false);
        }
        if (b instanceof ChecksumBuilder) {
          ((ChecksumBuilder<?>)b).correctChecksumAtBuild(false);
        }
      }
      p = builder.build();
    }

    this.payload = p;
  }

  /**
   *
   * @param builder
   */
  protected IcmpV6InvokingPacketPacket(Builder builder) {
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
  static abstract class Builder extends AbstractBuilder {

    private Packet payload;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    protected Builder(IcmpV6InvokingPacketPacket packet) {
      this.payload = packet.payload;
    }

    /**
     *
     * @param payload
     * @return this Builder object for method chaining.
     */
    public Builder payload(Packet payload) {
      this.payload = payload;
      return this;
    }

  }

}
