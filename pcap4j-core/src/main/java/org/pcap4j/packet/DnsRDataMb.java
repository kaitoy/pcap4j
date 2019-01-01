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
 * DNS MB RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   MADNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * MADNAME         A &lt;domain-name&gt; which specifies a host which has the
 *                 specified mailbox.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMb implements DnsRData {

  /** */
  private static final long serialVersionUID = -7237273314471356977L;

  private final DnsDomainName maDName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMb object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMb newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMb(rawData, offset, length);
  }

  private DnsRDataMb(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.maDName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataMb(Builder builder) {
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
        .append("MB RDATA:")
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
    DnsRDataMb other = (DnsRDataMb) obj;
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

    private Builder(DnsRDataMb obj) {
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

    /** @return a new DnsRDataMb object. */
    public DnsRDataMb build() {
      return new DnsRDataMb(this);
    }
  }
}
