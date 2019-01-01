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
 * DNS PTR RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                  PTRDNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * PTRDNAME        A &lt;domain-name&gt; which points to some location in the
 *                 domain name space.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataPtr implements DnsRData {

  /** */
  private static final long serialVersionUID = 3845617703457911405L;

  private final DnsDomainName ptrDName;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataPtr object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataPtr newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataPtr(rawData, offset, length);
  }

  private DnsRDataPtr(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.ptrDName = DnsDomainName.newInstance(rawData, offset, length);
  }

  private DnsRDataPtr(Builder builder) {
    if (builder == null || builder.ptrDName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.ptrDName: ").append(builder.ptrDName);
      throw new NullPointerException(sb.toString());
    }

    this.ptrDName = builder.ptrDName;
  }

  /** @return ptrDName */
  public DnsDomainName getPtrDName() {
    return ptrDName;
  }

  @Override
  public int length() {
    return ptrDName.length();
  }

  @Override
  public byte[] getRawData() {
    return ptrDName.getRawData();
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
        .append("PTR RDATA:")
        .append(ls)
        .append(indent)
        .append("  PTRDNAME: ")
        .append(headerRawData != null ? ptrDName.toString(headerRawData) : ptrDName.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return ptrDName.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    DnsRDataPtr other = (DnsRDataPtr) obj;
    return ptrDName.equals(other.ptrDName);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName ptrDName;

    /** */
    public Builder() {}

    private Builder(DnsRDataPtr obj) {
      this.ptrDName = obj.ptrDName;
    }

    /**
     * @param ptrDName ptrDName
     * @return this Builder object for method chaining.
     */
    public Builder ptrDName(DnsDomainName ptrDName) {
      this.ptrDName = ptrDName;
      return this;
    }

    /** @return a new DnsRDataPtr object. */
    public DnsRDataPtr build() {
      return new DnsRDataPtr(this);
    }
  }
}
