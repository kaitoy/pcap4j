/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class UnknownIpV6Option implements IpV6Option {

  /** */
  private static final long serialVersionUID = -2090004757469984967L;

  private final IpV6OptionType type;
  private final byte dataLen;
  private final byte[] data;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownIpV6Option object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownIpV6Option newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownIpV6Option(rawData, offset, length);
  }

  private UnknownIpV6Option(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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

    this.type = IpV6OptionType.getInstance(rawData[offset]);
    this.dataLen = rawData[1 + offset];
    if (length - 2 < this.dataLen) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
          .append(this.dataLen + 2)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.data = ByteArrays.getSubArray(rawData, 2 + offset, dataLen);
  }

  private UnknownIpV6Option(Builder builder) {
    if (builder == null || builder.type == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.type: ")
          .append(builder.type)
          .append(" builder.data: ")
          .append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.type = builder.type;
    this.data = new byte[builder.data.length];
    System.arraycopy(builder.data, 0, this.data, 0, builder.data.length);

    if (builder.correctLengthAtBuild) {
      this.dataLen = (byte) data.length;
    } else {
      this.dataLen = builder.dataLen;
    }
  }

  @Override
  public IpV6OptionType getType() {
    return type;
  }

  /** @return dataLen */
  public byte getDataLen() {
    return dataLen;
  }

  /** @return dataLen */
  public int getDataLenAsInt() {
    return 0xFF & dataLen;
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
    rawData[0] = type.value();
    rawData[1] = dataLen;
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
    sb.append("[Option Type: ")
        .append(type)
        .append("] [Option Data Len: ")
        .append(getDataLenAsInt())
        .append(" bytes] [Option Data: 0x")
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

    UnknownIpV6Option other = (UnknownIpV6Option) obj;
    return type.equals(other.type) && dataLen == other.dataLen && Arrays.equals(data, other.data);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + type.hashCode();
    result = 31 * result + dataLen;
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder implements LengthBuilder<UnknownIpV6Option> {

    private IpV6OptionType type;
    private byte dataLen;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownIpV6Option option) {
      this.type = option.type;
      this.dataLen = option.dataLen;
      this.data = option.data;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV6OptionType type) {
      this.type = type;
      return this;
    }

    /**
     * @param dataLen dataLen
     * @return this Builder object for method chaining.
     */
    public Builder dataLen(byte dataLen) {
      this.dataLen = dataLen;
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
    public UnknownIpV6Option build() {
      return new UnknownIpV6Option(this);
    }
  }
}
