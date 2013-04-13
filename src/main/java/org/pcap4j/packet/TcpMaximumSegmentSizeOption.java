/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
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

  /**
   *
   */
  private static final long serialVersionUID = 7552907605220130850L;

  private final TcpOptionKind kind = TcpOptionKind.MAXIMUM_SEGMENT_SIZE;
  private final byte length;
  private final short maxSegSize;

  /**
   *
   * @param rawData
   * @return a new TcpMaximumSegmentSizeOption object.
   */
  public static TcpMaximumSegmentSizeOption newInstance(byte[] rawData) {
    return new TcpMaximumSegmentSizeOption(rawData);
  }

  private TcpMaximumSegmentSizeOption(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0] != kind.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The kind must be: ")
        .append(kind.valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[1] != 4) {
      throw new IllegalRawDataException(
                  "Invalid value of length field: " + rawData[1]
                );
    }

    this.length = rawData[1];
    this.maxSegSize = ByteArrays.getShort(rawData, 2);
  }

  private TcpMaximumSegmentSizeOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.maxSegSize = builder.maxSegSize;

    if (builder.correctLengthAtBuild) {
      this.length = (byte)length();
    }
    else {
      this.length = builder.length;
    }
  }

  public TcpOptionKind getKind() {
    return kind;
  }

  /**
   *
   * @return length
   */
  public byte getLength() { return length; }

  /**
   *
   * @return length
   */
  public int getLengthAsInt() { return 0xFF & length; }

  /**
   *
   * @return maxSegSize
   */
  public short getMaxSegSize() { return maxSegSize; }

  /**
   *
   * @return maxSegSize
   */
  public int getMaxSegSizeAsInt() { return 0xFFFF & maxSegSize; }

  public int length() { return 4; }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    rawData[2] = (byte)(maxSegSize >> 8);
    rawData[3] = (byte)maxSegSize;
    return rawData;
  }

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ")
      .append(kind);
    sb.append("] Length: ")
      .append(getLengthAsInt());
    sb.append(" bytes] [Maximum Segment Size: ")
      .append(getMaxSegSizeAsInt());
    sb.append(" bytes]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    return Arrays.equals((getClass().cast(obj)).getRawData(), getRawData());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class Builder
  implements LengthBuilder<TcpMaximumSegmentSizeOption> {

    private byte length;
    private short maxSegSize;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(TcpMaximumSegmentSizeOption option) {
      this.length = option.length;
      this.maxSegSize = option.maxSegSize;
    }

    /**
     *
     * @param length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     *
     * @param maxSegSize
     * @return this Builder object for method chaining.
     */
    public Builder maxSegSize(short maxSegSize) {
      this.maxSegSize = maxSegSize;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    public TcpMaximumSegmentSizeOption build() {
      return new TcpMaximumSegmentSizeOption(this);
    }

  }

}
