/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS CAA RDATA
 *
 * <pre style="white-space: pre;">
 * +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
 * | Flags          | Tag Length = n |
 * +----------------+----------------+...+---------------+
 * | Tag char 0     | Tag char 1     |...| Tag char n-1  |
 * +----------------+----------------+...+---------------+
 * +----------------+----------------+.....+----------------+
 * | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
 * +----------------+----------------+.....+----------------+
 * (m = d - n - 2) where d is the length of the RDATA section.)
 *
 * where:
 * Flags: One octet containing bit flags for record. See rfc for details.
 * Tag: The property identifier, a sequence of US-ASCII characters.
 * Value: A sequence of octets representing the property value.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6844">RFC 6844</a>
 * @author Paulo Pacheco
 * @since pcap4j 1.7.2
 */
public final class DnsRDataCaa implements DnsRData {

  private static final int CAA_RR_MIN_LEN = 6 /* Do not accept empty tag values */;

  /** A serial UID for serialization. */
  private static final long serialVersionUID = -1015182073420031158L;

  private final int flags;
  private final String tag;
  private final String value;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataCaa object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataCaa newInstance(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataCaa(rawData, offset, length);
  }

  private DnsRDataCaa(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < CAA_RR_MIN_LEN) {
      throw new IllegalRawDataException("The data is too short to build a DnsRDataCaa");
    }

    this.flags = ByteArrays.getByte(rawData, offset) & 0xFF;

    /* Reading single property entry consisting of a tag-value pair. */

    /* Read tag */
    int cursor = 1;
    int tagLen = rawData[offset + cursor] & 0xFF;
    cursor++; /* tag len */
    this.tag = new String(rawData, offset + cursor, tagLen);
    cursor += tagLen;

    /* Read value */
    this.value = new String(rawData, offset + cursor, length - cursor);
  }

  private DnsRDataCaa(Builder builder) {
    if (builder == null || builder.tag == null || builder.value == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.tag: ").append(builder.tag)
        .append(" builder.value: ").append(builder.value);
      throw new NullPointerException(sb.toString());
    }

    if (builder.flags > 255 || builder.flags < 0) {
      StringBuilder sb = new StringBuilder();
      sb.append("Invalid value for flags: ").append(builder.flags);
      throw new IllegalArgumentException(sb.toString());
    }

    this.flags = builder.flags;

    /* TODO: validate if tag follows rfc rules.

     Tag values MAY contain US-ASCII characters 'a' through 'z', 'A'
     through 'Z', and the numbers 0 through 9.  Tag values SHOULD NOT
     contain any other characters.  Matching of tag values is case
     insensitive.

     Tag values submitted for registration by IANA MUST NOT contain any
     characters other than the (lowercase) US-ASCII characters 'a'
     through 'z' and the numbers 0 through 9.
     */
    this.tag = builder.tag;
    this.value = builder.value;
  }

  @Override
  public int length() {
    return 1 + 1 + tag.length() + value.length();
  }

  @Override
  public byte[] getRawData() {
    byte rawData[] = new byte[this.length()];

    rawData[0] = (byte) this.flags;
    rawData[1] = (byte) this.tag.length();
    int cursor = 2;

    System.arraycopy(this.tag.getBytes(), 0, rawData, cursor, this.tag.length());
    cursor += this.tag.length();

    System.arraycopy(this.value.getBytes(), 0, rawData, cursor, this.value.length());

    return rawData;
  }

  /**
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString(String indent) {
    String ls = System.getProperty("line.separator");

    StringBuilder sb = new StringBuilder();
    sb.append(indent).append("CAA RDATA:").append(ls);
    sb.append(indent);
    sb.append("  CAA: ");
    sb.append(this.flags);
    sb.append(" ");
    sb.append(this.tag);
    sb.append(" ");
    sb.append(this.value);
    sb.append(ls);

    return sb.toString();
  }

  @Override
  public String toString() {
    return toString("");
  }

  @Override
  public String toString(String indent, byte[] headerRawData) {
    // TODO Auto-generated method stub.
    // I don't know where this is called with headerRawData
    return toString(indent);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    org.pcap4j.packet.DnsRDataCaa that = (org.pcap4j.packet.DnsRDataCaa) o;

    if (flags != that.flags) {
      return false;
    }
    if (!tag.equals(that.tag)) {
      return false;
    }
    return value.equals(that.value);
  }

  @Override
  public int hashCode() {
    int result = flags;
    result = 31 * result + tag.hashCode();
    result = 31 * result + value.hashCode();
    return result;
  }

  /**
   * @author Paulo Pacheco
   * @since pcap4j 1.7.2
   */
  public static final class Builder {

    private int flags;
    private String tag;
    private String value;

    public Builder() {}

    private Builder(DnsRDataCaa obj) {
      this.flags = obj.flags;
      this.tag = obj.tag;
      this.value = obj.value;
    }

    /**
     * @param flags flags
     * @return this Builder object for method chaining.
     */
    public Builder flags(int flags) {
      this.flags = flags;
      return this;
    }

    /**
     * @param flags flags
     * @return this Builder object for method chaining.
     */
    public Builder flags(byte flags) {
      this.flags = flags & 0xFF;
      return this;
    }

    /**
     * @param tag tag
     * @return this Builder object for method chaining.
     */
    public Builder tag(String tag) {
      this.tag = tag;
      return this;
    }

    /**
     * @param value value
     * @return this Builder object for method chaining.
     */
    public Builder value(String value) {
      this.value = value;
      return this;
    }

    /**
     * @return a new DnsRDataCaa object.
     */
    public DnsRDataCaa build() {
          return new DnsRDataCaa(this);
      }
  }

}
