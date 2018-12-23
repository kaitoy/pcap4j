/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.pcap4j.util.ByteArrays;

/**
 * https://tools.ietf.org/html/rfc1661
 *
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
abstract class AbstractPppPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 9184646119975504414L;

  private final Packet payload;
  private final byte[] pad;

  protected AbstractPppPacket(byte[] rawData, int offset, int length, AbstractPppHeader header)
      throws IllegalRawDataException {
    int payloadAndPadLength = length - header.length();
    if (payloadAndPadLength > 0) {
      int payloadOffset = offset + header.length();
      this.payload =
          PacketFactories.getFactory(Packet.class, PppDllProtocol.class)
              .newInstance(rawData, payloadOffset, payloadAndPadLength, header.getProtocol());

      int padLength = payloadAndPadLength - payload.length();
      if (padLength > 0) {
        this.pad = ByteArrays.getSubArray(rawData, payloadOffset + payload.length(), padLength);
      } else {
        this.pad = new byte[0];
      }
    } else {
      this.payload = null;
      this.pad = new byte[0];
    }
  }

  protected AbstractPppPacket(Builder builder) {
    if (builder == null || builder.protocol == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.protocol: ").append(builder.protocol);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    if (builder.pad != null && builder.pad.length != 0) {
      this.pad = new byte[builder.pad.length];
      System.arraycopy(builder.pad, 0, this.pad, 0, builder.pad.length);
    } else {
      this.pad = new byte[0];
    }
  }

  @Override
  public abstract AbstractPppHeader getHeader();

  @Override
  public Packet getPayload() {
    return payload;
  }

  /** @return pad */
  public byte[] getPad() {
    byte[] copy = new byte[pad.length];
    System.arraycopy(pad, 0, copy, 0, pad.length);
    return copy;
  }

  @Override
  protected int calcLength() {
    int length = super.calcLength();
    length += pad.length;
    return length;
  }

  @Override
  protected byte[] buildRawData() {
    byte[] rawData = super.buildRawData();
    if (pad.length != 0) {
      System.arraycopy(pad, 0, rawData, rawData.length - pad.length, pad.length);
    }
    return rawData;
  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();

    sb.append(getHeader().toString());
    if (payload != null) {
      sb.append(payload.toString());
    }
    if (pad.length != 0) {
      String ls = System.getProperty("line.separator");
      sb.append("[PPP Pad (")
          .append(pad.length)
          .append(" bytes)]")
          .append(ls)
          .append("  Hex stream: ")
          .append(ByteArrays.toHexString(pad, " "))
          .append(ls);
    }

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (super.equals(obj)) {
      AbstractPppPacket other = (AbstractPppPacket) obj;
      return Arrays.equals(pad, other.pad);
    } else {
      return false;
    }
  }

  @Override
  protected int calcHashCode() {
    return 31 * super.calcHashCode() + Arrays.hashCode(pad);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  abstract static class Builder extends AbstractBuilder {

    private PppDllProtocol protocol;
    private Packet.Builder payloadBuilder;
    private byte[] pad;

    /** */
    public Builder() {}

    protected Builder(AbstractPppPacket packet) {
      this.protocol = packet.getHeader().protocol;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
      this.pad = packet.pad;
    }

    /**
     * @param protocol protocol
     * @return this Builder object for method chaining.
     */
    public Builder protocol(PppDllProtocol protocol) {
      this.protocol = protocol;
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

    /**
     * @param pad pad
     * @return this Builder object for method chaining.
     */
    public Builder pad(byte[] pad) {
      this.pad = pad;
      return this;
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  abstract static class AbstractPppHeader extends AbstractHeader {

    /*
     * +----------+-------------+---------+
     * | Protocol | Information | Padding |
     * | 8/16 bits|      *      |    *    |
     * +----------+-------------+---------+
     */

    /** */
    private static final long serialVersionUID = -9126636226651383452L;

    private static final int PROTOCOL_OFFSET = 0;
    private static final int PROTOCOL_SIZE = SHORT_SIZE_IN_BYTES;
    static final int PPP_HEADER_SIZE = PROTOCOL_OFFSET + PROTOCOL_SIZE;

    private final PppDllProtocol protocol;

    protected AbstractPppHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < PPP_HEADER_SIZE) {
        this.protocol = null; // Subclass has to throw an IllegalRawDataException.
      } else {
        try {
          this.protocol =
              PppDllProtocol.getInstance(ByteArrays.getShort(rawData, PROTOCOL_OFFSET + offset));
        } catch (IllegalArgumentException e) {
          throw new IllegalRawDataException(e);
        }
      }
    }

    protected AbstractPppHeader(Builder builder) {
      this.protocol = builder.protocol;
    }

    /** @return protocol */
    public PppDllProtocol getProtocol() {
      return protocol;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(protocol.value()));
      return rawFields;
    }

    @Override
    public int length() {
      return PPP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[PPP Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Protocol: ").append(protocol).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      AbstractPppHeader other = (AbstractPppHeader) obj;
      return protocol.equals(other.protocol);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + protocol.hashCode();
      return result;
    }
  }
}
