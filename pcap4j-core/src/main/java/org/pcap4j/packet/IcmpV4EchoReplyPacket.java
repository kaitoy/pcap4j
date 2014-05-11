/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

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
   */
  public static IcmpV4EchoReplyPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    return new IcmpV4EchoReplyPacket(rawData);
  }

  private IcmpV4EchoReplyPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV4EchoReplyHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = UnknownPacket.newPacket(rawPayload);
  }

  private IcmpV4EchoReplyPacket(Builder builder) {
    super(builder);

    if (builder.payloadBuilder == null) {
      throw new NullPointerException("builder.payloadBuilder must not be null");
    }

    this.payload = builder.payloadBuilder.build();
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
      this.payloadBuilder = packet.payload.getBuilder();
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
