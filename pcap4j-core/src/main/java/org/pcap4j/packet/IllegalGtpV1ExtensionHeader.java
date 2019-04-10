/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.GtpV1Packet.GtpV1ExtensionHeader;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Leo Ma
 * @since pcap4j 1.7.7
 */
public final class IllegalGtpV1ExtensionHeader implements GtpV1ExtensionHeader {

  /** */
  private static final long serialVersionUID = 2799097946096468881L;

  private final GtpV1ExtensionHeaderType nextExtensionHeaderType;
  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IllegalGtpV1ExtensionHeader object.
   */
  public static IllegalGtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalGtpV1ExtensionHeader(rawData, offset, length);
  }

  private IllegalGtpV1ExtensionHeader(byte[] rawData, int offset, int length) {
    this.nextExtensionHeaderType =
        GtpV1ExtensionHeaderType.getInstance(rawData[offset + length - 1]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalGtpV1ExtensionHeader(Builder builder) {
    if (builder == null || builder.nextExtensionHeaderType == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextExtensionHeaderType: ")
          .append(builder.nextExtensionHeaderType)
          .append(" builder.rawData: ")
          .append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    this.nextExtensionHeaderType = builder.nextExtensionHeaderType;
    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(builder.rawData, 0, this.rawData, 0, builder.rawData.length);
  }

  @Override
  public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
    return nextExtensionHeaderType;
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, rawData.length);
    return copy;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[illegal data: ").append(ByteArrays.toHexString(rawData, "")).append("]");
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

    IllegalGtpV1ExtensionHeader other = (IllegalGtpV1ExtensionHeader) obj;
    return Arrays.equals(other.rawData, rawData);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(rawData);
  }

  public static final class Builder {

    private GtpV1ExtensionHeaderType nextExtensionHeaderType;
    private byte[] rawData;

    /** */
    public Builder() {}

    private Builder(IllegalGtpV1ExtensionHeader option) {
      this.nextExtensionHeaderType = option.nextExtensionHeaderType;
      this.rawData = option.rawData;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(GtpV1ExtensionHeaderType type) {
      this.nextExtensionHeaderType = nextExtensionHeaderType;
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

    /** @return a new IllegalGtpV1ExtensionHeader object. */
    public IllegalGtpV1ExtensionHeader build() {
      return new IllegalGtpV1ExtensionHeader(this);
    }
  }
}
