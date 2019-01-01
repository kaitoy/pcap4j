/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS MX RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                  PREFERENCE                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   EXCHANGE                    /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * PREFERENCE      A 16 bit integer which specifies the preference given to
 *                 this RR among others at the same owner.  Lower values
 *                 are preferred.
 *
 * EXCHANGE        A &lt;domain-name&gt; which specifies a host willing to act as
 *                 a mail exchange for the owner name.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMx implements DnsRData {

  /** */
  private static final long serialVersionUID = -5914050306503756427L;

  private final short preference;
  private final DnsDomainName exchange;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMx object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMx newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMx(rawData, offset, length);
  }

  private DnsRDataMx(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < SHORT_SIZE_IN_BYTES + 1) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a DnsRDataMx (")
          .append(SHORT_SIZE_IN_BYTES + 1)
          .append(" bytes at least). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.preference = ByteArrays.getShort(rawData, offset);
    this.exchange =
        DnsDomainName.newInstance(
            rawData, offset + SHORT_SIZE_IN_BYTES, length - SHORT_SIZE_IN_BYTES);
  }

  private DnsRDataMx(Builder builder) {
    if (builder == null || builder.exchange == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.exchange: ").append(builder.exchange);
      throw new NullPointerException(sb.toString());
    }

    this.preference = builder.preference;
    this.exchange = builder.exchange;
  }

  /** @return preference */
  public short getPreference() {
    return preference;
  }

  /** @return preference */
  public int getPreferenceAsInt() {
    return preference;
  }

  /** @return exchange */
  public DnsDomainName getExchange() {
    return exchange;
  }

  @Override
  public int length() {
    return exchange.length() + 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] exRawData = exchange.getRawData();
    byte[] data = new byte[exRawData.length + 2];
    System.arraycopy(ByteArrays.toByteArray(preference), 0, data, 0, SHORT_SIZE_IN_BYTES);
    System.arraycopy(exRawData, 0, data, SHORT_SIZE_IN_BYTES, exRawData.length);
    return data;
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
        .append("MX RDATA:")
        .append(ls)
        .append(indent)
        .append("  PREFERENCE: ")
        .append(preference)
        .append(ls)
        .append(indent)
        .append("  EXCHANGE: ")
        .append(headerRawData != null ? exchange.toString(headerRawData) : exchange.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + exchange.hashCode();
    result = prime * result + preference;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    DnsRDataMx other = (DnsRDataMx) obj;
    if (!exchange.equals(other.exchange)) {
      return false;
    }
    if (preference != other.preference) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private short preference;
    private DnsDomainName exchange;

    /** */
    public Builder() {}

    private Builder(DnsRDataMx obj) {
      this.preference = obj.preference;
      this.exchange = obj.exchange;
    }

    /**
     * @param preference preference
     * @return this Builder object for method chaining.
     */
    public Builder preference(short preference) {
      this.preference = preference;
      return this;
    }

    /**
     * @param exchange exchange
     * @return this Builder object for method chaining.
     */
    public Builder exchange(DnsDomainName exchange) {
      this.exchange = exchange;
      return this;
    }

    /** @return a new DnsRDataMx object. */
    public DnsRDataMx build() {
      return new DnsRDataMx(this);
    }
  }
}
