/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS MR RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   NEWNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * NEWNAME         A &lt;domain-name&gt; which specifies a mailbox which is the
 *                 proper rename of the specified mailbox.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMr implements DnsRData {

  /** */
  private static final long serialVersionUID = 3960543085797464866L;

  private final DnsDomainName newName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMr object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMr newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMr(rawData, offset, length);
  }

  private DnsRDataMr(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.newName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataMr(Builder builder) {
    if (builder == null || builder.newName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.newName: ").append(builder.newName);
      throw new NullPointerException(sb.toString());
    }

    this.newName = builder.newName;
  }

  /** @return newName */
  public DnsDomainName getNewName() {
    return newName;
  }

  @Override
  public int length() {
    return newName.length();
  }

  @Override
  public byte[] getRawData() {
    return newName.getRawData();
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return convertToString("", null);
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
        .append("MR RDATA:")
        .append(ls)
        .append(indent)
        .append("  NEWNAME: ")
        .append(headerRawData != null ? newName.toString(headerRawData) : newName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return newName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataMr other = (DnsRDataMr) obj;
    return newName.equals(other.newName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName newName;

    /** */
    public Builder() {}

    private Builder(DnsRDataMr obj) {
      this.newName = obj.newName;
    }

    /**
     * @param newName newName
     * @return this Builder object for method chaining.
     */
    public Builder newName(DnsDomainName newName) {
      this.newName = newName;
      return this;
    }

    /** @return a new DnsRDataMr object. */
    public DnsRDataMr build() {
      return new DnsRDataMr(this);
    }
  }
}
