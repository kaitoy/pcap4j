/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DnsClass;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.util.ByteArrays;

/**
 * DNS Resource record
 *
 * <pre style="white-space: pre;">
 *                                 1  1  1  1  1  1
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                                               /
 * /                      NAME                     /
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 * /                     RDATA                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsResourceRecord implements Serializable {

  /** */
  private static final long serialVersionUID = 4951400991563055073L;

  private final DnsDomainName name;
  private final DnsResourceRecordType dataType;
  private final DnsClass dataClass;
  private final int ttl;
  private final short rdLength;
  private final DnsRData rData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsResourceRecord object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsResourceRecord newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsResourceRecord(rawData, offset, length);
  }

  private DnsResourceRecord(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    int cursor = 0;
    this.name = DnsDomainName.newInstance(rawData, offset, length);
    cursor += name.length();

    if (length - cursor < SHORT_SIZE_IN_BYTES * 3 + INT_SIZE_IN_BYTES) {
      StringBuilder sb = new StringBuilder(200);
      sb.append(
              "The data is too short to build type, class, ttl, and rdlength of DnsResourceRecord. "
                  + "data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }

    this.dataType =
        DnsResourceRecordType.getInstance(ByteArrays.getShort(rawData, offset + cursor));
    cursor += SHORT_SIZE_IN_BYTES;
    this.dataClass = DnsClass.getInstance(ByteArrays.getShort(rawData, offset + cursor));
    cursor += SHORT_SIZE_IN_BYTES;
    this.ttl = ByteArrays.getInt(rawData, offset + cursor);
    cursor += INT_SIZE_IN_BYTES;
    this.rdLength = ByteArrays.getShort(rawData, offset + cursor);
    cursor += SHORT_SIZE_IN_BYTES;

    int rdLen = getRdLengthAsInt();
    if (length - cursor < rdLen) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build rData of DnsResourceRecord (")
          .append(rdLen)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor)
          .append(", dataType: ")
          .append(dataType);
      throw new IllegalRawDataException(sb.toString());
    }

    if (rdLen != 0) {
      this.rData =
          PacketFactories.getFactory(DnsRData.class, DnsResourceRecordType.class)
              .newInstance(rawData, offset + cursor, rdLen, dataType);
    } else {
      this.rData = null;
    }
  }

  private DnsResourceRecord(Builder builder) {
    if (builder == null
        || builder.name == null
        || builder.dataType == null
        || builder.dataClass == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder")
          .append(builder)
          .append(" builder.name: ")
          .append(builder.name)
          .append(" builder.dataType: ")
          .append(builder.dataType)
          .append(" builder.dataClass: ")
          .append(builder.dataClass);
      throw new NullPointerException(sb.toString());
    }

    this.name = builder.name;
    this.dataType = builder.dataType;
    this.dataClass = builder.dataClass;
    this.ttl = builder.ttl;
    this.rData = builder.rData;

    if (builder.correctLengthAtBuild) {
      int rdLen = rData == null ? 0 : rData.length();
      if ((rdLen & 0xFFFF0000) != 0) {
        throw new IllegalArgumentException(
            "(rData.length() & 0xFFFF0000) must be zero. rData: " + rData);
      }
      this.rdLength = (short) rdLen;
    } else {
      this.rdLength = builder.rdLength;
    }
  }

  /** @return name */
  public DnsDomainName getName() {
    return name;
  }

  /** @return dataType */
  public DnsResourceRecordType getDataType() {
    return dataType;
  }

  /** @return dataClass */
  public DnsClass getDataClass() {
    return dataClass;
  }

  /** @return ttl */
  public int getTtl() {
    return ttl;
  }

  /** @return ttl */
  public long getTtlAsLong() {
    return ttl & 0xFFFFFFFFL;
  }

  /** @return rdLength */
  public short getRdLength() {
    return rdLength;
  }

  /** @return rdLength */
  public int getRdLengthAsInt() {
    return rdLength & 0xFFFF;
  }

  /** @return rData. May be null. */
  public DnsRData getRData() {
    return rData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;

    byte[] rawName = name.getRawData();
    System.arraycopy(rawName, 0, data, 0, rawName.length);
    cursor += rawName.length;
    System.arraycopy(
        ByteArrays.toByteArray(dataType.value()), 0, data, cursor, SHORT_SIZE_IN_BYTES);
    cursor += SHORT_SIZE_IN_BYTES;
    System.arraycopy(
        ByteArrays.toByteArray(dataClass.value()), 0, data, cursor, SHORT_SIZE_IN_BYTES);
    cursor += SHORT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(ttl), 0, data, cursor, INT_SIZE_IN_BYTES);
    cursor += INT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(rdLength), 0, data, cursor, SHORT_SIZE_IN_BYTES);
    if (rData != null) {
      cursor += SHORT_SIZE_IN_BYTES;
      byte[] rawRData = rData.getRawData();
      System.arraycopy(rawRData, 0, data, cursor, rawRData.length);
    }

    return data;
  }

  /** @return length */
  public int length() {
    int rDataLen = rData == null ? 0 : rData.length();
    return name.length() + SHORT_SIZE_IN_BYTES * 3 + INT_SIZE_IN_BYTES + rDataLen;
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
   * @param headerRawData the raw data of the DNS header including this resource record.
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
        .append("NAME: ")
        .append(headerRawData != null ? name.toString(headerRawData) : name)
        .append(ls)
        .append(indent)
        .append("TYPE: ")
        .append(dataType)
        .append(ls)
        .append(indent)
        .append("CLASS: ")
        .append(dataClass)
        .append(ls)
        .append(indent)
        .append("TTL: ")
        .append(getTtlAsLong())
        .append(ls)
        .append(indent)
        .append("RDLENGTH: ")
        .append(getRdLengthAsInt())
        .append(ls);
    if (rData != null) {
      sb.append(indent)
          .append("RDATA:")
          .append(ls)
          .append(
              headerRawData != null
                  ? rData.toString(indent + "  ", headerRawData)
                  : rData.toString(indent + "  "));
    }

    return sb.toString();
  }

  @Override
  public int hashCode() {
    int result = name.hashCode();
    result = 31 * result + dataType.hashCode();
    result = 31 * result + dataClass.hashCode();
    result = 31 * result + ttl;
    result = 31 * result + (int) rdLength;
    result = 31 * result + (rData != null ? rData.hashCode() : 0);
    return result;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    DnsResourceRecord that = (DnsResourceRecord) o;

    if (ttl != that.ttl) {
      return false;
    }
    if (rdLength != that.rdLength) {
      return false;
    }
    if (!name.equals(that.name)) {
      return false;
    }
    if (!dataType.equals(that.dataType)) {
      return false;
    }
    if (!dataClass.equals(that.dataClass)) {
      return false;
    }
    return rData != null ? rData.equals(that.rData) : that.rData == null;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder implements LengthBuilder<DnsResourceRecord> {

    private DnsDomainName name;
    private DnsResourceRecordType dataType;
    private DnsClass dataClass;
    private int ttl;
    private short rdLength;
    private DnsRData rData;
    private boolean correctLengthAtBuild = false;

    /** */
    public Builder() {}

    private Builder(DnsResourceRecord obj) {
      this.name = obj.name;
      this.dataType = obj.dataType;
      this.dataClass = obj.dataClass;
      this.ttl = obj.ttl;
      this.rdLength = obj.rdLength;
      this.rData = obj.rData;
    }

    /**
     * @param name name
     * @return this Builder object for method chaining.
     */
    public Builder name(DnsDomainName name) {
      this.name = name;
      return this;
    }

    /**
     * @param dataType dataType
     * @return this Builder object for method chaining.
     */
    public Builder dataType(DnsResourceRecordType dataType) {
      this.dataType = dataType;
      return this;
    }

    /**
     * @param dataClass dataClass
     * @return this Builder object for method chaining.
     */
    public Builder dataClass(DnsClass dataClass) {
      this.dataClass = dataClass;
      return this;
    }

    /**
     * @param ttl ttl
     * @return this Builder object for method chaining.
     */
    public Builder ttl(int ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     * @param rdLength rdLength
     * @return this Builder object for method chaining.
     */
    public Builder rdLength(short rdLength) {
      this.rdLength = rdLength;
      return this;
    }

    /**
     * @param rData rData
     * @return this Builder object for method chaining.
     */
    public Builder rData(DnsRData rData) {
      this.rData = rData;
      return this;
    }

    @Override
    public LengthBuilder<DnsResourceRecord> correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    /** @return a new DnsResourceRecord object. */
    @Override
    public DnsResourceRecord build() {
      return new DnsResourceRecord(this);
    }
  }

  /**
   * The interface representing an RDATA. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV4Option newInstance(byte[] rawData, int offset, int
   * length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public interface DnsRData extends Serializable {

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();

    /**
     * @param indent indent
     * @return String representation of this object.
     */
    public String toString(String indent);

    /**
     * @param indent indent
     * @param headerRawData the raw data of the DNS header including this RDATA.
     * @return String representation of this object.
     */
    public String toString(String indent, byte[] headerRawData);
  }
}
