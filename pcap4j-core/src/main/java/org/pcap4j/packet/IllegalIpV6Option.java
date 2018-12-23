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
public final class IllegalIpV6Option implements IpV6Option {

  /** */
  private static final long serialVersionUID = -1186786850549984010L;

  private final IpV6OptionType type;
  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IllegalIpV6Option object.
   */
  public static IllegalIpV6Option newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalIpV6Option(rawData, offset, length);
  }

  private IllegalIpV6Option(byte[] rawData, int offset, int length) {
    this.type = IpV6OptionType.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalIpV6Option(Builder builder) {
    if (builder == null || builder.type == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.optionType: ")
          .append(builder.type)
          .append(" builder.rawData: ")
          .append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    this.type = builder.type;
    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(builder.rawData, 0, this.rawData, 0, builder.rawData.length);
  }

  @Override
  public IpV6OptionType getType() {
    return type;
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
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
        .append("] [Illegal Raw Data: 0x")
        .append(ByteArrays.toHexString(rawData, ""))
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

    IllegalIpV6Option other = (IllegalIpV6Option) obj;
    return type.equals(other.type) && Arrays.equals(other.rawData, rawData);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + type.hashCode();
    result = 31 * result + Arrays.hashCode(rawData);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder {

    private IpV6OptionType type;
    private byte[] rawData;

    /** */
    public Builder() {}

    private Builder(IllegalIpV6Option option) {
      this.type = option.type;
      this.rawData = option.rawData;
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
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /** @return a new IllegalIpV6Option object. */
    public IllegalIpV6Option build() {
      return new IllegalIpV6Option(this);
    }
  }
}
