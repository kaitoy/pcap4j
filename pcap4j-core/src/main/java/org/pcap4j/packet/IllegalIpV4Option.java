/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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
public final class IllegalIpV4Option implements IpV4Option {

  /**
   *
   */
  private static final long serialVersionUID = -5887663161675479542L;

  private final IpV4OptionType type;
  private final byte[] rawData;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData
   * @param offset
   * @param length
   * @return a new IllegalIpV4Option object.
   */
  public static IllegalIpV4Option newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalIpV4Option(rawData, offset, length);
  }

  private IllegalIpV4Option(byte[] rawData, int offset, int length) {
    this.type = IpV4OptionType.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalIpV4Option(Builder builder) {
    if (
        builder == null
     || builder.type == null
     || builder.rawData == null
   ) {
     StringBuilder sb = new StringBuilder();
     sb.append("builder: ").append(builder)
       .append(" builder.type: ").append(builder.type)
       .append(" builder.rawData: ").append(builder.rawData);
     throw new NullPointerException(sb.toString());
   }

   this.type = builder.type;
   this.rawData = new byte[builder.rawData.length];
   System.arraycopy(
     builder.rawData, 0, this.rawData, 0, builder.rawData.length
   );
  }

  public IpV4OptionType getType() { return type; }

  public int length() { return rawData.length; }

  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
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
    sb.append("[option-type: ")
      .append(type)
      .append("] [Illegal Raw Data: 0x")
      .append(ByteArrays.toHexString(rawData, ""))
      .append("]");
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
   * @since pcap4j 0.9.11
   */
  public static final class Builder {

    private IpV4OptionType type;
    private byte[] rawData;

    /**
     *
     */
    public Builder() {}

    private Builder(IllegalIpV4Option option) {
      this.type = option.type;
      this.rawData = option.rawData;
    }

    /**
     *
     * @param type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV4OptionType type) {
      this.type = type;
      return this;
    }

    /**
     *
     * @param rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /**
     *
     * @return a new IllegalIpV4Option object.
     */
    public IllegalIpV4Option build() {
      return new IllegalIpV4Option(this);
    }

  }

}
