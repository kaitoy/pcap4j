/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import org.pcap4j.packet.namednumber.DnsClass;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.util.ByteArrays;

/**
 * DNS Question
 *
 * <pre style="white-space: pre;">
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsQuestion implements Serializable {

  /** */
  private static final long serialVersionUID = -709060058515052575L;

  private final DnsDomainName qName;
  private final DnsResourceRecordType qType;
  private final DnsClass qClass;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsQuestion object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsQuestion newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsQuestion(rawData, offset, length);
  }

  private DnsQuestion(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    int cursor = 0;
    this.qName = DnsDomainName.newInstance(rawData, offset, length);
    cursor += qName.length();

    if (length - cursor < SHORT_SIZE_IN_BYTES * 2) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build qType an qClass of DnsQuestion. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }
    this.qType = DnsResourceRecordType.getInstance(ByteArrays.getShort(rawData, offset + cursor));
    cursor += SHORT_SIZE_IN_BYTES;
    this.qClass = DnsClass.getInstance(ByteArrays.getShort(rawData, offset + cursor));
  }

  private DnsQuestion(Builder builder) {
    if (builder == null
        || builder.qName == null
        || builder.qType == null
        || builder.qClass == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder")
          .append(builder)
          .append(" builder.qName: ")
          .append(builder.qName)
          .append(" builder.qType: ")
          .append(builder.qType)
          .append(" builder.qClass: ")
          .append(builder.qClass);
      throw new NullPointerException(sb.toString());
    }

    this.qName = builder.qName;
    this.qType = builder.qType;
    this.qClass = builder.qClass;
  }

  /** @return qName */
  public DnsDomainName getQName() {
    return qName;
  }

  /** @return qType */
  public DnsResourceRecordType getQType() {
    return qType;
  }

  /** @return qClass */
  public DnsClass getQClass() {
    return qClass;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;

    byte[] rawQName = qName.getRawData();
    System.arraycopy(rawQName, 0, data, 0, rawQName.length);
    cursor += rawQName.length;
    System.arraycopy(ByteArrays.toByteArray(qType.value()), 0, data, cursor, SHORT_SIZE_IN_BYTES);
    cursor += SHORT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(qClass.value()), 0, data, cursor, SHORT_SIZE_IN_BYTES);

    return data;
  }

  /** @return length */
  public int length() {
    return qName.length() + SHORT_SIZE_IN_BYTES * 2;
  }

  @Override
  public String toString() {
    return convertToString("", null);
  }

  /**
   * @param indent indent
   * @return String representation of this object.
   */
  public String toString(String indent) {
    return convertToString(indent, null);
  }

  /**
   * @param indent indent
   * @param headerRawData the raw data of the DNS header including this question.
   * @return String representation of this object.
   */
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
        .append("QNAME: ")
        .append(headerRawData != null ? qName.toString(headerRawData) : qName)
        .append(ls)
        .append(indent)
        .append("QTYPE: ")
        .append(qType)
        .append(ls)
        .append(indent)
        .append("QCLASS: ")
        .append(qClass)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + qClass.hashCode();
    result = prime * result + qName.hashCode();
    result = prime * result + qType.hashCode();
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
    DnsQuestion other = (DnsQuestion) obj;
    if (!qClass.equals(other.qClass)) {
      return false;
    }
    if (!qName.equals(other.qName)) {
      return false;
    }
    if (!qType.equals(other.qType)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName qName;
    private DnsResourceRecordType qType;
    private DnsClass qClass;

    /** */
    public Builder() {}

    private Builder(DnsQuestion obj) {
      this.qName = obj.qName;
      this.qType = obj.qType;
      this.qClass = obj.qClass;
    }

    /**
     * @param qName qName
     * @return this Builder object for method chaining.
     */
    public Builder qName(DnsDomainName qName) {
      this.qName = qName;
      return this;
    }

    /**
     * @param qType qType
     * @return this Builder object for method chaining.
     */
    public Builder qType(DnsResourceRecordType qType) {
      this.qType = qType;
      return this;
    }

    /**
     * @param qClass qClass
     * @return this Builder object for method chaining.
     */
    public Builder qClass(DnsClass qClass) {
      this.qClass = qClass;
      return this;
    }

    /** @return a new DnsQuestion object. */
    public DnsQuestion build() {
      return new DnsQuestion(this);
    }
  }
}
