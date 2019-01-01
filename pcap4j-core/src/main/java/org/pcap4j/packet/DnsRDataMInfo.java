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
 * DNS MINFO RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                    RMAILBX                    /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                    EMAILBX                    /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * RMAILBX         A &lt;domain-name&gt; which specifies a mailbox which is
 *                 responsible for the mailing list or mailbox.  If this
 *                 domain name names the root, the owner of the MINFO RR is
 *                 responsible for itself.  Note that many existing mailing
 *                 lists use a mailbox X-request for the RMAILBX field of
 *                 mailing list X, e.g., Msgroup-request for Msgroup.  This
 *                 field provides a more general mechanism.
 *
 *
 * EMAILBX         A &lt;domain-name&gt; which specifies a mailbox which is to
 *                 receive error messages related to the mailing list or
 *                 mailbox specified by the owner of the MINFO RR (similar
 *                 to the ERRORS-TO: field which has been proposed).  If
 *                 this domain name names the root, errors should be
 *                 returned to the sender of the message.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataMInfo implements DnsRData {

  /** */
  private static final long serialVersionUID = 3803968528398017544L;

  private final DnsDomainName rMailBx;
  private final DnsDomainName eMailBx;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataMInfo object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataMInfo newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataMInfo(rawData, offset, length);
  }

  private DnsRDataMInfo(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.rMailBx = DnsDomainName.newInstance(rawData, offset, length);
    int rMailBxLen = rMailBx.length();
    if (rMailBxLen == length) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build eMailBx in DnsRDataMInfo. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.eMailBx = DnsDomainName.newInstance(rawData, offset + rMailBxLen, length - rMailBxLen);
  }

  private DnsRDataMInfo(Builder builder) {
    if (builder == null || builder.rMailBx == null || builder.eMailBx == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.rMailBx: ")
          .append(builder.rMailBx)
          .append(" builder.eMailBx: ")
          .append(builder.eMailBx);
      throw new NullPointerException(sb.toString());
    }

    this.rMailBx = builder.rMailBx;
    this.eMailBx = builder.eMailBx;
  }

  /** @return rMailBx */
  public DnsDomainName getRMailBx() {
    return rMailBx;
  }

  /** @return eMailBx */
  public DnsDomainName getEMailBx() {
    return eMailBx;
  }

  @Override
  public int length() {
    return rMailBx.length() + eMailBx.length();
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;

    byte[] rawRMailBx = rMailBx.getRawData();
    System.arraycopy(rawRMailBx, 0, data, cursor, rawRMailBx.length);
    cursor += rawRMailBx.length;

    byte[] rawEMailBx = eMailBx.getRawData();
    System.arraycopy(rawEMailBx, 0, data, cursor, rawEMailBx.length);

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
        .append("MINFO RDATA:")
        .append(ls)
        .append(indent)
        .append("  RMAILBX: ")
        .append(headerRawData != null ? rMailBx.toString(headerRawData) : rMailBx.toString())
        .append(ls)
        .append(indent)
        .append("  EMAILBX: ")
        .append(headerRawData != null ? eMailBx.toString(headerRawData) : eMailBx.toString())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + rMailBx.hashCode();
    result = prime * result + eMailBx.hashCode();
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
    DnsRDataMInfo other = (DnsRDataMInfo) obj;
    if (!rMailBx.equals(other.rMailBx)) {
      return false;
    }
    if (!eMailBx.equals(other.eMailBx)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName rMailBx;
    private DnsDomainName eMailBx;

    /** */
    public Builder() {}

    private Builder(DnsRDataMInfo obj) {
      this.rMailBx = obj.rMailBx;
      this.eMailBx = obj.eMailBx;
    }

    /**
     * @param rMailBx rMailBx
     * @return this Builder object for method chaining.
     */
    public Builder rMailBx(DnsDomainName rMailBx) {
      this.rMailBx = rMailBx;
      return this;
    }

    /**
     * @param eMailBx eMailBx
     * @return this Builder object for method chaining.
     */
    public Builder eMailBx(DnsDomainName eMailBx) {
      this.eMailBx = eMailBx;
      return this;
    }

    /** @return a new DnsRDataMInfo object. */
    public DnsRDataMInfo build() {
      return new DnsRDataMInfo(this);
    }
  }
}
