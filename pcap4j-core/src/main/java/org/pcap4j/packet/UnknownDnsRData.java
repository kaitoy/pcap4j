/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class UnknownDnsRData implements DnsRData {

  /** */
  private static final long serialVersionUID = 2491230520019980578L;

  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownDnsRData object.
   */
  public static UnknownDnsRData newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownDnsRData(rawData, offset, length);
  }

  private UnknownDnsRData(byte[] rawData, int offset, int length) {
    this.rawData = ByteArrays.getSubArray(rawData, offset, length);
  }

  private UnknownDnsRData(Builder builder) {
    if (builder == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.rawData: ").append(builder.rawData);
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

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString(String indent) {
    return convertToString(indent, null);
  }

  @Override
  public String toString(String indent, byte[] headerRawData) {
    if (headerRawData == null) {
      throw new NullPointerException("headerRawData is null.");
    }
    return convertToString(indent, headerRawData);
  }

  private String convertToString(String indent, byte[] headerRawData) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("Unknown Data:")
        .append(ls)
        .append(indent)
        .append("  data: ")
        .append(ByteArrays.toHexString(rawData, ""))
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(rawData);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    UnknownDnsRData other = (UnknownDnsRData) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private byte[] rawData;

    /** */
    public Builder() {}

    private Builder(UnknownDnsRData obj) {
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

    /** @return a new UnknownDnsRData object. */
    public UnknownDnsRData build() {
      return new UnknownDnsRData(this);
    }
  }
}
