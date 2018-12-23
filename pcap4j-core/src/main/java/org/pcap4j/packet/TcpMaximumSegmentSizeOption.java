/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpMaximumSegmentSizeOption implements TcpOption {

  /*
   *  +--------+--------+--------+--------+
   *  |00000010|00000100|   max seg size  |
   *  +--------+--------+--------+--------+
   *   Kind=2   Length=4
   */

  /** */
  private static final long serialVersionUID = 7552907605220130850L;

  private final TcpOptionKind kind = TcpOptionKind.MAXIMUM_SEGMENT_SIZE;
  private final byte length;
  private final short maxSegSize;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new TcpMaximumSegmentSizeOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static TcpMaximumSegmentSizeOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new TcpMaximumSegmentSizeOption(rawData, offset, length);
  }

  private TcpMaximumSegmentSizeOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 3. rawData: ")
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
    if (this.length != 4) {
      throw new IllegalRawDataException("Invalid value of length field: " + this.length);
    }

    this.maxSegSize = ByteArrays.getShort(rawData, 2 + offset);
  }

  private TcpMaximumSegmentSizeOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.maxSegSize = builder.maxSegSize;

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

  /** @return maxSegSize */
  public short getMaxSegSize() {
    return maxSegSize;
  }

  /** @return maxSegSize */
  public int getMaxSegSizeAsInt() {
    return 0xFFFF & maxSegSize;
  }

  @Override
  public int length() {
    return 4;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    rawData[2] = (byte) (maxSegSize >> 8);
    rawData[3] = (byte) maxSegSize;
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ").append(kind);
    sb.append("] [Length: ").append(getLengthAsInt());
    sb.append(" bytes] [Maximum Segment Size: ").append(getMaxSegSizeAsInt());
    sb.append(" bytes]");
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

    TcpMaximumSegmentSizeOption other = (TcpMaximumSegmentSizeOption) obj;
    return length == other.length && maxSegSize == other.maxSegSize;
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + maxSegSize;
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class Builder implements LengthBuilder<TcpMaximumSegmentSizeOption> {

    private byte length;
    private short maxSegSize;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(TcpMaximumSegmentSizeOption option) {
      this.length = option.length;
      this.maxSegSize = option.maxSegSize;
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
     * @param maxSegSize maxSegSize
     * @return this Builder object for method chaining.
     */
    public Builder maxSegSize(short maxSegSize) {
      this.maxSegSize = maxSegSize;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public TcpMaximumSegmentSizeOption build() {
      return new TcpMaximumSegmentSizeOption(this);
    }
  }
}
