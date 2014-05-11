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
public final class IcmpV4EchoPacket extends IcmpIdentifiablePacket {

  /**
   *
   */
  private static final long serialVersionUID = -122451430580609855L;

  private final IcmpV4EchoHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IcmpV4EchoPacket object
   * @throws IllegalRawDataException
   */
  public static IcmpV4EchoPacket newPacket(byte[] rawData) throws IllegalRawDataException {
    return new IcmpV4EchoPacket(rawData);
  }

  private IcmpV4EchoPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV4EchoHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = UnknownPacket.newPacket(rawPayload);
  }

  private IcmpV4EchoPacket(Builder builder) {
    super(builder);

    if (builder.payloadBuilder == null) {
      throw new NullPointerException("builder.payloadBuilder must not be null");
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IcmpV4EchoHeader(builder);
  }

  @Override
  public IcmpV4EchoHeader getHeader() {
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

    private Builder(IcmpV4EchoPacket packet) {
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
    public IcmpV4EchoPacket build() {
      return new IcmpV4EchoPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4EchoHeader extends IcmpIdentifiableHeader {

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
    private static final long serialVersionUID = -1302478674628547524L;

    private IcmpV4EchoHeader(byte[] rawData) throws IllegalRawDataException {
      super(rawData);
    }

    private IcmpV4EchoHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Echo Header";
    }

  }

}
