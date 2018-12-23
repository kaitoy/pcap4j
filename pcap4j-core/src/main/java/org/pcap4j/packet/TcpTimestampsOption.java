/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.0
 */
public final class TcpTimestampsOption implements TcpOption {

  /*
   * http://tools.ietf.org/html/draft-ietf-tcpm-1323bis-21
   *
   *   +-------+-------+---------------------+---------------------+
   *   |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
   *   +-------+-------+---------------------+---------------------+
   *       1       1              4                     4
   */

  /** */
  private static final long serialVersionUID = -7134215148170658739L;

  private final TcpOptionKind kind = TcpOptionKind.TIMESTAMPS;
  private final byte length;
  private final int tsValue;
  private final int tsEchoReply;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new TcpTimestampsOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static TcpTimestampsOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new TcpTimestampsOption(rawData, offset, length);
  }

  private TcpTimestampsOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 10) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 9. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[offset] != kind.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The kind must be: ")
          .append(kind.valueAsString())
          .append(" rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = rawData[1 + offset];
    if (this.length != 10) {
      throw new IllegalRawDataException("The value of length field must be 10 but: " + this.length);
    }

    this.tsValue = ByteArrays.getInt(rawData, 2 + offset);
    this.tsEchoReply = ByteArrays.getInt(rawData, 6 + offset);
  }

  private TcpTimestampsOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.tsValue = builder.tsValue;
    this.tsEchoReply = builder.tsEchoReply;

    if (builder.correctLengthAtBuild) {
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public TcpOptionKind getKind() {
    return kind;
  }

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return tsValue */
  public int getTsValue() {
    return tsValue;
  }

  /** @return tsValue */
  public long getTsValueAsLong() {
    return 0xFFFFFFFFL & tsValue;
  }

  /** @return tsEchoReply */
  public int getTsEchoReply() {
    return tsEchoReply;
  }

  /** @return tsEchoReply */
  public long getTsEchoReplyAsLong() {
    return 0xFFFFFFFFL & tsEchoReply;
  }

  @Override
  public int length() {
    return 10;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    System.arraycopy(ByteArrays.toByteArray(tsValue), 0, rawData, 2, ByteArrays.INT_SIZE_IN_BYTES);
    System.arraycopy(
        ByteArrays.toByteArray(tsEchoReply), 0, rawData, 6, ByteArrays.INT_SIZE_IN_BYTES);
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ")
        .append(kind)
        .append("] [Length: ")
        .append(getLengthAsInt())
        .append(" bytes] [TS Value: ")
        .append(getTsValueAsLong())
        .append("] [TS Echo Reply: ")
        .append(getTsEchoReplyAsLong())
        .append("]");
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

    TcpTimestampsOption other = (TcpTimestampsOption) obj;
    return length == other.length && tsValue == other.tsValue && tsEchoReply == other.tsEchoReply;
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + tsValue;
    result = 31 * result + tsEchoReply;
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.2.0
   */
  public static final class Builder implements LengthBuilder<TcpTimestampsOption> {

    private byte length;
    private int tsValue;
    private int tsEchoReply;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(TcpTimestampsOption option) {
      this.length = option.length;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     * @param tsValue tsValue
     * @return this Builder object for method chaining.
     */
    public Builder tsValue(int tsValue) {
      this.tsValue = tsValue;
      return this;
    }

    /**
     * @param tsEchoReply tsEchoReply
     * @return this Builder object for method chaining.
     */
    public Builder tsEchoReply(int tsEchoReply) {
      this.tsEchoReply = tsEchoReply;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public TcpTimestampsOption build() {
      return new TcpTimestampsOption(this);
    }
  }
}
