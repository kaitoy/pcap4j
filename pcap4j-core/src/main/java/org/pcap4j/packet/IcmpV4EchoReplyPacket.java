/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4EchoReplyPacket extends IcmpIdentifiablePacket {

  /** */
  private static final long serialVersionUID = -7353440327689688935L;

  private final IcmpV4EchoReplyHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV4EchoReplyPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV4EchoReplyPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV4EchoReplyPacket(rawData, offset, length);
  }

  private IcmpV4EchoReplyPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV4EchoReplyHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, NotApplicable.class)
              .newInstance(rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
    } else {
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
  public static final class Builder extends org.pcap4j.packet.IcmpIdentifiablePacket.Builder {

    private Packet.Builder payloadBuilder;

    /** */
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
  public static final class IcmpV4EchoReplyHeader extends IcmpIdentifiableHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 8044479519522316613L;

    private IcmpV4EchoReplyHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);
    }

    private IcmpV4EchoReplyHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Echo Reply Header";
    }
  }
}
