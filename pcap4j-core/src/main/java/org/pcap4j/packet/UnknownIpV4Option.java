/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class UnknownIpV4Option implements IpV4Option {

  /** */
  private static final long serialVersionUID = 5843622351774970021L;

  private final IpV4OptionType type;
  private final byte length;
  private final byte[] data;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownIpV4Option object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownIpV4Option newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownIpV4Option(rawData, offset, length);
  }

  private UnknownIpV4Option(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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

    this.type = IpV4OptionType.getInstance(rawData[offset]);
    this.length = rawData[1 + offset];
    int lengthFieldAsInt = getLengthAsInt();
    if (length < lengthFieldAsInt) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option (")
          .append(lengthFieldAsInt)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.data = ByteArrays.getSubArray(rawData, 2 + offset, lengthFieldAsInt - 2);
  }

  private UnknownIpV4Option(Builder builder) {
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
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public IpV4OptionType getType() {
    return type;
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
    rawData[0] = type.value();
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
    sb.append("[option-type: ")
        .append(type)
        .append("] [option-length: ")
        .append(getLengthAsInt())
        .append(" bytes] [option-data: 0x")
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

    UnknownIpV4Option other = (UnknownIpV4Option) obj;
    return type.equals(other.type) && length == other.length && Arrays.equals(data, other.data);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + type.hashCode();
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder implements LengthBuilder<UnknownIpV4Option> {

    private IpV4OptionType type;
    private byte length;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownIpV4Option option) {
      this.type = option.type;
      this.length = option.length;
      this.data = option.data;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV4OptionType type) {
      this.type = type;
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
    public UnknownIpV4Option build() {
      return new UnknownIpV4Option(this);
    }
  }
}
