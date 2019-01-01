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
 * DNS NS RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   NSDNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * NSDNAME         A &lt;domain-name&gt; which specifies a host which should be
 *                 authoritative for the specified class and domain.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataNs implements DnsRData {

  /** */
  private static final long serialVersionUID = -5232680288519805322L;

  private final DnsDomainName nsDName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataNs object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataNs newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataNs(rawData, offset, length);
  }

  private DnsRDataNs(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.nsDName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataNs(Builder builder) {
    if (builder == null || builder.nsDName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.nsDName: ").append(builder.nsDName);
      throw new NullPointerException(sb.toString());
    }

    this.nsDName = builder.nsDName;
  }

  /** @return nsDName */
  public DnsDomainName getNsDName() {
    return nsDName;
  }

  @Override
  public int length() {
    return nsDName.length();
  }

  @Override
  public byte[] getRawData() {
    return nsDName.getRawData();
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
        .append("NS RDATA:")
        .append(ls)
        .append(indent)
        .append("  NSDNAME: ")
        .append(headerRawData != null ? nsDName.toString(headerRawData) : nsDName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return nsDName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataNs other = (DnsRDataNs) obj;
    return nsDName.equals(other.nsDName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName nsDName;

    /** */
    public Builder() {}

    private Builder(DnsRDataNs obj) {
      this.nsDName = obj.nsDName;
    }

    /**
     * @param nsDName nsDName
     * @return this Builder object for method chaining.
     */
    public Builder nsDName(DnsDomainName nsDName) {
      this.nsDName = nsDName;
      return this;
    }

    /** @return a new DnsRDataNs object. */
    public DnsRDataNs build() {
      return new DnsRDataNs(this);
    }
  }
}
