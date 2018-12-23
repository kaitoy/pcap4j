/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS HINFO RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                      CPU                      /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                       OS                      /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * CPU             A &lt;character-string&gt; which specifies the CPU type.
 *
 * OS              A &lt;character-string&gt; which specifies the operating
 *                 system type.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataHInfo implements DnsRData {

  /** */
  private static final long serialVersionUID = -4910328276617707827L;

  private final String cpu;
  private final String os;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataHInfo object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataHInfo newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataHInfo(rawData, offset, length);
  }

  private DnsRDataHInfo(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    int cpuLen = rawData[offset] & 0xFF;
    int cursor = 1;
    if (cpuLen + 1 > length - cursor) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build cpu and os in DnsRDataHInfo. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }
    this.cpu = new String(rawData, offset + cursor, cpuLen);
    cursor += cpuLen;

    int osLen = rawData[offset + cursor] & 0xFF;
    cursor++;
    if (osLen > length - cursor) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build os in DnsRDataHInfo (")
          .append(osLen)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length)
          .append(", cursor: ")
          .append(cursor);
      throw new IllegalRawDataException(sb.toString());
    }
    this.os = new String(rawData, offset + cursor, osLen);
  }

  private DnsRDataHInfo(Builder builder) {
    if (builder == null || builder.cpu == null || builder.os == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.cpu: ")
          .append(builder.cpu)
          .append(" builder.os: ")
          .append(builder.os);
      throw new NullPointerException(sb.toString());
    }
    if (builder.cpu.getBytes().length > 255) {
      throw new IllegalArgumentException(
          "Length of cpu must be less than 256. cpu: " + builder.cpu);
    }
    if (builder.os.getBytes().length > 255) {
      throw new IllegalArgumentException("Length of os must be less than 256. os: " + builder.os);
    }

    this.cpu = builder.cpu;
    this.os = builder.os;
  }

  /** @return cpu */
  public String getCpu() {
    return cpu;
  }

  /** @return os */
  public String getOs() {
    return os;
  }

  @Override
  public int length() {
    return cpu.getBytes().length + os.getBytes().length + 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;

    byte[] rawCpu = cpu.getBytes();
    data[cursor] = (byte) rawCpu.length;
    cursor++;
    System.arraycopy(rawCpu, 0, data, cursor, rawCpu.length);
    cursor += rawCpu.length;

    byte[] rawOs = os.getBytes();
    data[cursor] = (byte) rawOs.length;
    cursor++;
    System.arraycopy(rawOs, 0, data, cursor, rawOs.length);

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
        .append("HINFO RDATA:")
        .append(ls)
        .append(indent)
        .append("  CPU: ")
        .append(cpu)
        .append(ls)
        .append(indent)
        .append("  OS: ")
        .append(os)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + cpu.hashCode();
    result = prime * result + os.hashCode();
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
    DnsRDataHInfo other = (DnsRDataHInfo) obj;
    if (!cpu.equals(other.cpu)) {
      return false;
    }
    if (!os.equals(other.os)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private String cpu;
    private String os;

    /** */
    public Builder() {}

    private Builder(DnsRDataHInfo obj) {
      this.cpu = obj.cpu;
      this.os = obj.os;
    }

    /**
     * @param cpu cpu
     * @return this Builder object for method chaining.
     */
    public Builder cpu(String cpu) {
      this.cpu = cpu;
      return this;
    }

    /**
     * @param os os
     * @return this Builder object for method chaining.
     */
    public Builder os(String os) {
      this.os = os;
      return this;
    }

    /** @return a new DnsRDataHInfo object. */
    public DnsRDataHInfo build() {
      return new DnsRDataHInfo(this);
    }
  }
}
