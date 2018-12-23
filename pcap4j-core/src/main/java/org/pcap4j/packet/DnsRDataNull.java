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
 * DNS NULL RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                  &lt;anything&gt;                   /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * Anything at all may be in the RDATA field so long as it is 65535 octets or less.
 * </pre>
 *
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataNull implements DnsRData {

  /** */
  private static final long serialVersionUID = -8881175833056081958L;

  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataNull object.
   */
  public static DnsRDataNull newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataNull(rawData, offset, length);
  }

  private DnsRDataNull(byte[] rawData, int offset, int length) {
    this.rawData = ByteArrays.getSubArray(rawData, offset, length);
  }

  private DnsRDataNull(Builder builder) {
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
        .append("NULL RDATA:")
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
    DnsRDataNull other = (DnsRDataNull) obj;
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

    private Builder(DnsRDataNull obj) {
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

    /** @return a new DnsRDataNull object. */
    public DnsRDataNull build() {
      return new DnsRDataNull(this);
    }
  }
}
