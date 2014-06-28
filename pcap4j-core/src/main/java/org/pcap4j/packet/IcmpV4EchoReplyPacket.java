/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4EchoReplyPacket extends IcmpIdentifiablePacket {

  /**
   *
   */
  private static final long serialVersionUID = -7353440327689688935L;

  private final IcmpV4EchoReplyHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IcmpV4EchoReplyPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IcmpV4EchoReplyPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IcmpV4EchoReplyPacket(rawData);
  }

  private IcmpV4EchoReplyPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV4EchoReplyHeader(rawData);

    int payloadLength = rawData.length - header.length();
    if (payloadLength > 0) {
      byte[] rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
      this.payload
        = PacketFactories.getFactory(Packet.class, NA.class).newInstance(rawPayload);
    }
    else {
      this.payload = null;
    }
  }

  private IcmpV4EchoReplyPacket(Builder builder) {
    super(builder);
    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IcmpV4EchoReplyHeader(builder);
  }

  @Override
  public IcmpV4EchoReplyHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class Builder extends org.pcap4j.packet.IcmpIdentifiablePacket.Builder {

    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4EchoReplyPacket packet) {
      super(packet);
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    @Override
    public Builder identifier(short identifier) {
      super.identifier(identifier);
      return this;
    }

    @Override
    public Builder sequenceNumber(short sequenceNumber) {
      super.sequenceNumber(sequenceNumber);
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    @Override
    public Packet.Builder getPayloadBuilder() {
      return payloadBuilder;
    }

    @Override
    public IcmpV4EchoReplyPacket build() {
      return new IcmpV4EchoReplyPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class IcmpV4EchoReplyHeader extends IcmpIdentifiableHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 8044479519522316613L;

    private IcmpV4EchoReplyHeader(byte[] rawData) throws IllegalRawDataException {
      super(rawData);
    }

    private IcmpV4EchoReplyHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Echo Reply Header";
    }

  }

}
