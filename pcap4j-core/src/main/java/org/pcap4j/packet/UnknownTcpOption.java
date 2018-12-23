/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
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
public final class UnknownTcpOption implements TcpOption {

  /** */
  private static final long serialVersionUID = -893085251311518110L;

  private final TcpOptionKind kind;
  private final byte length;
  private final byte[] data;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownTcpOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownTcpOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownTcpOption(rawData, offset, length);
  }

  private UnknownTcpOption(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 1. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.kind = TcpOptionKind.getInstance(rawData[offset]);
    this.length = rawData[1 + offset];
    if (length < this.length) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
          .append(this.length)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    if (this.length > 2) this.data = ByteArrays.getSubArray(rawData, 2 + offset, this.length - 2);
    else this.data = new byte[] {};
  }

  private UnknownTcpOption(Builder builder) {
    if (builder == null || builder.kind == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.kind: ")
          .append(builder.kind)
          .append(" builder.data: ")
          .append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.kind = builder.kind;
    this.data = new byte[builder.data.length];
    System.arraycopy(builder.data, 0, this.data, 0, builder.data.length);

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

  /** @return data */
  public byte[] getData() {
    byte[] copy = new byte[data.length];
    System.arraycopy(data, 0, copy, 0, data.length);
    return copy;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    System.arraycopy(data, 0, rawData, 2, data.length);
    return rawData;
  }

  @Override
  public int length() {
    return data.length + 2;
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
        .append(" bytes] [Data: 0x")
        .append(ByteArrays.toHexString(data, ""))
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

    UnknownTcpOption other = (UnknownTcpOption) obj;
    return kind.equals(other.kind) && length == other.length && Arrays.equals(data, other.data);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + kind.hashCode();
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder implements LengthBuilder<UnknownTcpOption> {

    private TcpOptionKind kind;
    private byte length;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownTcpOption option) {
      this.kind = option.kind;
      this.length = option.length;
      this.data = option.data;
    }

    /**
     * @param kind kind
     * @return this Builder object for method chaining.
     */
    public Builder kind(TcpOptionKind kind) {
      this.kind = kind;
      return this;
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
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(byte[] data) {
      this.data = data;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public UnknownTcpOption build() {
      return new UnknownTcpOption(this);
    }
  }
}
