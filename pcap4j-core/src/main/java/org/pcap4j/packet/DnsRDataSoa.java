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
 * DNS SOA RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     MNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                     RNAME                     /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    SERIAL                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    REFRESH                    |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     RETRY                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    EXPIRE                     |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    MINIMUM                    |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * MNAME           The &lt;domain-name&gt; of the name server that was the
 *                 original or primary source of data for this zone.
 *
 * RNAME           A &lt;domain-name&gt; which specifies the mailbox of the
 *                 person responsible for this zone.
 *
 * SERIAL          The unsigned 32 bit version number of the original copy
 *                 of the zone.  Zone transfers preserve this value.  This
 *                 value wraps and should be compared using sequence space
 *                 arithmetic.
 *
 * REFRESH         A 32 bit time interval before the zone should be
 *                 refreshed.
 *
 * RETRY           A 32 bit time interval that should elapse before a
 *                 failed refresh should be retried.
 *
 * EXPIRE          A 32 bit time value that specifies the upper limit on
 *                 the time interval that can elapse before the zone is no
 *                 longer authoritative.
 *
 * MINIMUM         The unsigned 32 bit minimum TTL field that should be
 *                 exported with any RR from this zone.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataSoa implements DnsRData {

  /** */
  private static final long serialVersionUID = -5916011849950625284L;

  private final DnsDomainName mName;
  private final DnsDomainName rName;
  private final int serial;
  private final int refresh;
  private final int retry;
  private final int expire;
  private final int minimum;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataSoa object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataSoa newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataSoa(rawData, offset, length);
  }

  private DnsRDataSoa(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    int cursor = 0;
    this.mName = DnsDomainName.newInstance(rawData, offset, length);
    int mNameLen = mName.length();
    cursor += mNameLen;
    if (cursor == length) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build rName in DnsRDataSoa. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }

    this.rName = DnsDomainName.newInstance(rawData, offset + cursor, length - cursor);
    int rNameLen = rName.length();
    cursor += rNameLen;
    if (cursor + INT_SIZE_IN_BYTES * 5 > length) {
      StringBuilder sb = new StringBuilder(200);
      sb.append(
              "The data is too short to build serial, refresh, retry, expire, and minimum"
                  + "in DnsRDataSoa. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }

    this.serial = ByteArrays.getInt(rawData, offset + cursor);
    cursor += INT_SIZE_IN_BYTES;
    this.refresh = ByteArrays.getInt(rawData, offset + cursor);
    cursor += INT_SIZE_IN_BYTES;
    this.retry = ByteArrays.getInt(rawData, offset + cursor);
    cursor += INT_SIZE_IN_BYTES;
    this.expire = ByteArrays.getInt(rawData, offset + cursor);
    cursor += INT_SIZE_IN_BYTES;
    this.minimum = ByteArrays.getInt(rawData, offset + cursor);
  }

  private DnsRDataSoa(Builder builder) {
    if (builder == null || builder.mName == null || builder.rName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.mName: ")
          .append(builder.mName)
          .append(" builder.rName: ")
          .append(builder.rName);
      throw new NullPointerException(sb.toString());
    }

    this.mName = builder.mName;
    this.rName = builder.rName;
    this.serial = builder.serial;
    this.refresh = builder.refresh;
    this.retry = builder.retry;
    this.expire = builder.expire;
    this.minimum = builder.minimum;
  }

  /** @return mName */
  public DnsDomainName getMName() {
    return mName;
  }

  /** @return rName */
  public DnsDomainName getRName() {
    return rName;
  }

  /** @return serial */
  public int getSerial() {
    return serial;
  }

  /** @return serial */
  public long getSerialAsLong() {
    return serial & 0xFFFFFFFFL;
  }

  /** @return refresh */
  public int getRefresh() {
    return refresh;
  }

  /** @return refresh */
  public long getRefreshAsLong() {
    return refresh & 0xFFFFFFFFL;
  }

  /** @return retry */
  public int getRetry() {
    return retry;
  }

  /** @return retry */
  public long getRetryAsLong() {
    return retry & 0xFFFFFFFFL;
  }

  /** @return expire */
  public int getExpire() {
    return expire;
  }

  /** @return expire */
  public long getExpireAsLong() {
    return expire & 0xFFFFFFFFL;
  }

  /** @return minimum */
  public int getMinimum() {
    return minimum;
  }

  /** @return minimum */
  public long getMinimumAsLong() {
    return minimum & 0xFFFFFFFFL;
  }

  @Override
  public int length() {
    return mName.length() + rName.length() + INT_SIZE_IN_BYTES * 5;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawMName = mName.getRawData();
    byte[] rawRName = rName.getRawData();
    byte[] data = new byte[rawMName.length + rawRName.length + INT_SIZE_IN_BYTES * 5];
    int cursor = 0;

    System.arraycopy(rawMName, 0, data, cursor, rawMName.length);
    cursor += rawMName.length;
    System.arraycopy(rawRName, 0, data, cursor, rawRName.length);
    cursor += rawRName.length;
    System.arraycopy(ByteArrays.toByteArray(serial), 0, data, cursor, INT_SIZE_IN_BYTES);
    cursor += INT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(refresh), 0, data, cursor, INT_SIZE_IN_BYTES);
    cursor += INT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(retry), 0, data, cursor, INT_SIZE_IN_BYTES);
    cursor += INT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(expire), 0, data, cursor, INT_SIZE_IN_BYTES);
    cursor += INT_SIZE_IN_BYTES;
    System.arraycopy(ByteArrays.toByteArray(minimum), 0, data, cursor, INT_SIZE_IN_BYTES);

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
        .append("SOA RDATA:")
        .append(ls)
        .append(indent)
        .append("  MNAME: ")
        .append(headerRawData != null ? mName.toString(headerRawData) : mName.toString())
        .append(ls)
        .append(indent)
        .append("  RNAME: ")
        .append(headerRawData != null ? rName.toString(headerRawData) : rName.toString())
        .append(ls)
        .append(indent)
        .append("  SERIAL: ")
        .append(getSerialAsLong())
        .append(ls)
        .append(indent)
        .append("  REFRESH: ")
        .append(getRefreshAsLong())
        .append(ls)
        .append(indent)
        .append("  RETRY: ")
        .append(getRetryAsLong())
        .append(ls)
        .append(indent)
        .append("  EXPIRE: ")
        .append(getExpireAsLong())
        .append(ls)
        .append(indent)
        .append("  MINIMUM: ")
        .append(getMinimumAsLong())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + expire;
    result = prime * result + mName.hashCode();
    result = prime * result + minimum;
    result = prime * result + rName.hashCode();
    result = prime * result + refresh;
    result = prime * result + retry;
    result = prime * result + serial;
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
    DnsRDataSoa other = (DnsRDataSoa) obj;
    if (expire != other.expire) {
      return false;
    }
    if (!mName.equals(other.mName)) {
      return false;
    }
    if (minimum != other.minimum) {
      return false;
    }
    if (!rName.equals(other.rName)) {
      return false;
    }
    if (refresh != other.refresh) {
      return false;
    }
    if (retry != other.retry) {
      return false;
    }
    if (serial != other.serial) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private DnsDomainName mName;
    private DnsDomainName rName;
    private int serial;
    private int refresh;
    private int retry;
    private int expire;
    private int minimum;

    /** */
    public Builder() {}

    private Builder(DnsRDataSoa obj) {
      this.mName = obj.mName;
      this.rName = obj.rName;
      this.serial = obj.serial;
      this.refresh = obj.refresh;
      this.retry = obj.retry;
      this.expire = obj.expire;
      this.minimum = obj.minimum;
    }

    /**
     * @param mName mName
     * @return this Builder object for method chaining.
     */
    public Builder mName(DnsDomainName mName) {
      this.mName = mName;
      return this;
    }

    /**
     * @param rName rName
     * @return this Builder object for method chaining.
     */
    public Builder rName(DnsDomainName rName) {
      this.rName = rName;
      return this;
    }

    /**
     * @param serial serial
     * @return this Builder object for method chaining.
     */
    public Builder serial(int serial) {
      this.serial = serial;
      return this;
    }

    /**
     * @param refresh refresh
     * @return this Builder object for method chaining.
     */
    public Builder refresh(int refresh) {
      this.refresh = refresh;
      return this;
    }

    /**
     * @param retry retry
     * @return this Builder object for method chaining.
     */
    public Builder retry(int retry) {
      this.retry = retry;
      return this;
    }

    /**
     * @param expire expire
     * @return this Builder object for method chaining.
     */
    public Builder expire(int expire) {
      this.expire = expire;
      return this;
    }

    /**
     * @param minimum minimum
     * @return this Builder object for method chaining.
     */
    public Builder minimum(int minimum) {
      this.minimum = minimum;
      return this;
    }

    /** @return a new DnsRDataSoa object. */
    public DnsRDataSoa build() {
      return new DnsRDataSoa(this);
    }
  }
}
