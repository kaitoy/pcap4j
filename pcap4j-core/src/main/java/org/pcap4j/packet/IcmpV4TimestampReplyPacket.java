/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4TimestampReplyPacket extends IcmpIdentifiablePacket {

  /** */
  private static final long serialVersionUID = 7638323748561226108L;

  private final IcmpV4TimestampReplyHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV4TimestampReplyPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV4TimestampReplyPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV4TimestampReplyPacket(rawData, offset, length);
  }

  private IcmpV4TimestampReplyPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV4TimestampReplyHeader(rawData, offset, length);
  }

  private IcmpV4TimestampReplyPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4TimestampReplyHeader(builder);
  }

  @Override
  public IcmpV4TimestampReplyHeader getHeader() {
    return header;
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

    private int originateTimestamp;
    private int receiveTimestamp;
    private int transmitTimestamp;

    /** */
    public Builder() {}

    private Builder(IcmpV4TimestampReplyPacket packet) {
      super(packet);
      this.originateTimestamp = packet.header.originateTimestamp;
      this.receiveTimestamp = packet.header.receiveTimestamp;
      this.transmitTimestamp = packet.header.transmitTimestamp;
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

    /**
     * @param originateTimestamp originateTimestamp
     * @return this Builder object for method chaining.
     */
    public Builder originateTimestamp(int originateTimestamp) {
      this.originateTimestamp = originateTimestamp;
      return this;
    }

    /**
     * @param receiveTimestamp receiveTimestamp
     * @return this Builder object for method chaining.
     */
    public Builder receiveTimestamp(int receiveTimestamp) {
      this.receiveTimestamp = receiveTimestamp;
      return this;
    }

    /**
     * @param transmitTimestamp transmitTimestamp
     * @return this Builder object for method chaining.
     */
    public Builder transmitTimestamp(int transmitTimestamp) {
      this.transmitTimestamp = transmitTimestamp;
      return this;
    }

    @Override
    public IcmpV4TimestampReplyPacket build() {
      return new IcmpV4TimestampReplyPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4TimestampReplyHeader extends IcmpIdentifiableHeader {

    /*
     * 0                               16                              32
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                 Originate Timestamp                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                   Receive Timestamp                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                  Transmit Timestamp                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /** */
    private static final long serialVersionUID = 8260989404858302787L;

    private static final int ORIGINATE_TIMESTAMP_OFFSET = ICMP_IDENTIFIABLE_HEADER_SIZE;
    private static final int ORIGINATE_TIMESTAMP_SIZE = INT_SIZE_IN_BYTES;
    private static final int RECEIVE_TIMESTAMP_OFFSET =
        ORIGINATE_TIMESTAMP_OFFSET + ORIGINATE_TIMESTAMP_SIZE;
    private static final int RECEIVE_TIMESTAMP_SIZE = INT_SIZE_IN_BYTES;
    private static final int TRANSMIT_TIMESTAMP_OFFSET =
        RECEIVE_TIMESTAMP_OFFSET + RECEIVE_TIMESTAMP_SIZE;
    private static final int TRANSMIT_TIMESTAMP_SIZE = INT_SIZE_IN_BYTES;
    private static final int ICMPV4_TIMESTAMP_HEADER_SIZE =
        TRANSMIT_TIMESTAMP_OFFSET + TRANSMIT_TIMESTAMP_SIZE;

    private final int originateTimestamp;
    private final int receiveTimestamp;
    private final int transmitTimestamp;

    private IcmpV4TimestampReplyHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);

      if (length < ICMPV4_TIMESTAMP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ")
            .append(getHeaderName())
            .append("(")
            .append(ICMPV4_TIMESTAMP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.originateTimestamp = ByteArrays.getInt(rawData, ORIGINATE_TIMESTAMP_OFFSET + offset);
      this.receiveTimestamp = ByteArrays.getInt(rawData, RECEIVE_TIMESTAMP_OFFSET + offset);
      this.transmitTimestamp = ByteArrays.getInt(rawData, TRANSMIT_TIMESTAMP_OFFSET + offset);
    }

    private IcmpV4TimestampReplyHeader(Builder builder) {
      super(builder);
      this.originateTimestamp = builder.originateTimestamp;
      this.receiveTimestamp = builder.receiveTimestamp;
      this.transmitTimestamp = builder.transmitTimestamp;
    }

    /** @return originateTimestamp */
    public int getOriginateTimestamp() {
      return originateTimestamp;
    }

    /** @return receiveTimestamp */
    public int getReceiveTimestamp() {
      return receiveTimestamp;
    }

    /** @return transmitTimestamp */
    public int getTransmitTimestamp() {
      return transmitTimestamp;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = super.getRawFields();
      rawFields.add(ByteArrays.toByteArray(originateTimestamp));
      rawFields.add(ByteArrays.toByteArray(receiveTimestamp));
      rawFields.add(ByteArrays.toByteArray(transmitTimestamp));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV4_TIMESTAMP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append(super.buildString());
      sb.append("  Originate Timestamp: ").append(originateTimestamp).append(ls);
      sb.append("  Receive Timestamp: ").append(receiveTimestamp).append(ls);
      sb.append("  Transmit Timestamp: ").append(transmitTimestamp).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (!super.equals(obj)) {
        return false;
      }

      IcmpV4TimestampReplyHeader other = (IcmpV4TimestampReplyHeader) obj;
      return originateTimestamp == other.originateTimestamp
          && receiveTimestamp == other.receiveTimestamp
          && transmitTimestamp == other.transmitTimestamp;
    }

    @Override
    protected int calcHashCode() {
      int result = super.calcHashCode();
      result = 31 * result + originateTimestamp;
      result = 31 * result + receiveTimestamp;
      result = 31 * result + transmitTimestamp;
      return result;
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Timestamp Reply Header";
    }
  }
}
