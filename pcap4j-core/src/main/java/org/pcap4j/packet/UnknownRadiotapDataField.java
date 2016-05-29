/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;

import org.pcap4j.packet.RadiotapPacket.RadiotapDataField;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class UnknownRadiotapDataField implements RadiotapDataField {

  /**
   *
   */
  private static final long serialVersionUID = 6405498375843386046L;

  private final byte[] rawData;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownRadiotapDataField object.
   */
  public static UnknownRadiotapDataField newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownRadiotapDataField(rawData, offset, length);
  }

  private UnknownRadiotapDataField(byte[] rawData, int offset, int length) {
    this.rawData = ByteArrays.getSubArray(rawData, offset, length);
  }

  private UnknownRadiotapDataField(Builder builder) {
    if (
         builder == null
      || builder.rawData == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.rawData: ").append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    this.rawData = ByteArrays.clone(builder.rawData);
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.clone(rawData);
  }

  /**
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Data: ")
      .append(ByteArrays.toHexString(rawData, ""))
      .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(rawData);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    UnknownRadiotapDataField other = (UnknownRadiotapDataField) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte[] rawData;

    /**
     *
     */
    public Builder() {}

    private Builder(UnknownRadiotapDataField obj) {
      this.rawData = obj.rawData;
    }

    /**
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /**
     * @return a new UnknownRadiotapDataField object.
     */
    public UnknownRadiotapDataField build() {
      return new UnknownRadiotapDataField(this);
    }

  }

}
