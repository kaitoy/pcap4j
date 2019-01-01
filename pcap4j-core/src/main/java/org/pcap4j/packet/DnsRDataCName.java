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
 * DNS CNAME RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     CNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * CNAME           A &lt;domain-name&gt; which specifies the canonical or primary
 *                 name for the owner.  The owner name is an alias.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataCName implements DnsRData {

  /** */
  private static final long serialVersionUID = 3515906031137985263L;

  private final DnsDomainName cName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataCname object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataCName newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataCName(rawData, offset, length);
  }

  private DnsRDataCName(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.cName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataCName(Builder builder) {
    if (builder == null || builder.cName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.cName: ").append(builder.cName);
      throw new NullPointerException(sb.toString());
    }

    this.cName = builder.cName;
  }

  /** @return cName */
  public DnsDomainName getCName() {
    return cName;
  }

  @Override
  public int length() {
    return cName.length();
  }

  @Override
  public byte[] getRawData() {
    return cName.getRawData();
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
        .append("CNAME RDATA:")
        .append(ls)
        .append(indent)
        .append("  CNAME: ")
        .append(headerRawData != null ? cName.toString(headerRawData) : cName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return cName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataCName other = (DnsRDataCName) obj;
    return cName.equals(other.cName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName cName;

    /** */
    public Builder() {}

    private Builder(DnsRDataCName obj) {
      this.cName = obj.cName;
    }

    /**
     * @param cName cName
     * @return this Builder object for method chaining.
     */
    public Builder cName(DnsDomainName cName) {
      this.cName = cName;
      return this;
    }

    /** @return a new DnsRDataCname object. */
    public DnsRDataCName build() {
      return new DnsRDataCName(this);
    }
  }
}
