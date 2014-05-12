/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6EchoRequestPacket extends IcmpIdentifiablePacket {

  /**
   *
   */
  private static final long serialVersionUID = 1447480467515593011L;

  private final IcmpV6EchoRequestHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IcmpV6EchoRequestPacket object
   * @throws IllegalRawDataException
   */
  public static IcmpV6EchoRequestPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    return new IcmpV6EchoRequestPacket(rawData);
  }

  private IcmpV6EchoRequestPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV6EchoRequestHeader(rawData);

    int payloadLength = rawData.length - header.length();
    if (payloadLength > 0) {
      byte[] rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
      this.payload = UnknownPacket.newPacket(rawPayload);
    }
    else {
      this.payload = null;
    }
  }

  private IcmpV6EchoRequestPacket(Builder builder) {
    super(builder);
    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IcmpV6EchoRequestHeader(builder);
  }

  @Override
  public IcmpV6EchoRequestHeader getHeader() {
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
   * @since pcap4j 0.9.15
   */
  public static
  final class Builder extends org.pcap4j.packet.IcmpIdentifiablePacket.Builder {

    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV6EchoRequestPacket packet) {
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
    public IcmpV6EchoRequestPacket build() {
      return new IcmpV6EchoRequestPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class IcmpV6EchoRequestHeader extends IcmpIdentifiableHeader {

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
    private static final long serialVersionUID = -6510139039546388892L;

    private IcmpV6EchoRequestHeader(byte[] rawData) throws IllegalRawDataException {
      super(rawData);
    }

    private IcmpV6EchoRequestHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "ICMPv6 Echo Request Header";
    }

  }

}
