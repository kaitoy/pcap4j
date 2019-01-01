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
 * DNS MF RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   MADNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * MADNAME         A &lt;domain-name&gt; which specifies a host which has a mail
 *                 agent for the domain which will accept mail for
 *                 forwarding to the domain.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMf implements DnsRData {

  /** */
  private static final long serialVersionUID = -3535653721390953465L;

  private final DnsDomainName maDName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMf object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMf newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMf(rawData, offset, length);
  }

  private DnsRDataMf(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.maDName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataMf(Builder builder) {
    if (builder == null || builder.maDName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.maDName: ").append(builder.maDName);
      throw new NullPointerException(sb.toString());
    }

    this.maDName = builder.maDName;
  }

  /** @return maDName */
  public DnsDomainName getMaDName() {
    return maDName;
  }

  @Override
  public int length() {
    return maDName.length();
  }

  @Override
  public byte[] getRawData() {
    return maDName.getRawData();
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
        .append("MF RDATA:")
        .append(ls)
        .append(indent)
        .append("  MADNAME: ")
        .append(headerRawData != null ? maDName.toString(headerRawData) : maDName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return maDName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataMf other = (DnsRDataMf) obj;
    return maDName.equals(other.maDName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName maDName;

    /** */
    public Builder() {}

    private Builder(DnsRDataMf obj) {
      this.maDName = obj.maDName;
    }

    /**
     * @param maDName maDName
     * @return this Builder object for method chaining.
     */
    public Builder maDName(DnsDomainName maDName) {
      this.maDName = maDName;
      return this;
    }

    /** @return a new DnsRDataMf object. */
    public DnsRDataMf build() {
      return new DnsRDataMf(this);
    }
  }
}
