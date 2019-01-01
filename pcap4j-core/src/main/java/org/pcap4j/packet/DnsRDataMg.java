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
 * DNS MG RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   MGMNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * MGMNAME         A &lt;domain-name&gt; which specifies a mailbox which is a
 *                 member of the mail group specified by the domain name.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMg implements DnsRData {

  /** */
  private static final long serialVersionUID = 884121664381530886L;

  private final DnsDomainName mgMName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMg object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMg newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMg(rawData, offset, length);
  }

  private DnsRDataMg(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.mgMName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataMg(Builder builder) {
    if (builder == null || builder.mgMName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.mgMName: ").append(builder.mgMName);
      throw new NullPointerException(sb.toString());
    }

    this.mgMName = builder.mgMName;
  }

  /** @return mgMName */
  public DnsDomainName getMgMName() {
    return mgMName;
  }

  @Override
  public int length() {
    return mgMName.length();
  }

  @Override
  public byte[] getRawData() {
    return mgMName.getRawData();
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
        .append("MG RDATA:")
        .append(ls)
        .append(indent)
        .append("  MGMNAME: ")
        .append(headerRawData != null ? mgMName.toString(headerRawData) : mgMName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return mgMName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataMg other = (DnsRDataMg) obj;
    return mgMName.equals(other.mgMName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName mgMName;

    /** */
    public Builder() {}

    private Builder(DnsRDataMg obj) {
      this.mgMName = obj.mgMName;
    }

    /**
     * @param mgMName mgMName
     * @return this Builder object for method chaining.
     */
    public Builder mgMName(DnsDomainName mgMName) {
      this.mgMName = mgMName;
      return this;
    }

    /** @return a new DnsRDataMg object. */
    public DnsRDataMg build() {
      return new DnsRDataMg(this);
    }
  }
}
