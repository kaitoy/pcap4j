/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet4Address;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS A RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ADDRESS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * ADDRESS         A 32 bit Internet address.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataA implements DnsRData {

  /**
   *
   */
  private static final long serialVersionUID = -3356048535448950943L;

  private final Inet4Address address;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataA object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataA newInstance(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataA(rawData, offset, length);
  }

  private DnsRDataA(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < INET4_ADDRESS_SIZE_IN_BYTES) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a DnsRDataA (")
        .append(INET4_ADDRESS_SIZE_IN_BYTES)
        .append(" bytes). data: ")
        .append(ByteArrays.toHexString(rawData, " "))
        .append(", offset: ")
        .append(offset)
        .append(", length: ")
        .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    this.address = ByteArrays.getInet4Address(rawData, offset);
  }

  private DnsRDataA(Builder builder) {
    if (
         builder == null
      || builder.address == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.address: ").append(builder.address);
      throw new NullPointerException(sb.toString());
    }

    this.address = builder.address;
  }

  /**
   * @return address
   */
  public Inet4Address getAddress() { return address; }

  @Override
  public int length() {
    return INET4_ADDRESS_SIZE_IN_BYTES;
  }

  @Override
  public byte[] getRawData() {
    return address.getAddress();
  }

  /**
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

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

    sb.append(indent).append("A RDATA:")
      .append(ls)
      .append(indent).append("  ADDRESS: ")
      .append(address.getHostAddress())
      .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return address.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    DnsRDataA other = (DnsRDataA) obj;
    return address.equals(other.address);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private Inet4Address address;

    /**
     *
     */
    public Builder() {}

    private Builder(DnsRDataA obj) {
      this.address = obj.address;
    }

    /**
     * @param address address
     * @return this Builder object for method chaining.
     */
    public Builder address(Inet4Address address) {
      this.address = address;
      return this;
    }

    /**
     * @return a new DnsRDataA object.
     */
    public DnsRDataA build() {
      return new DnsRDataA(this);
    }

  }

}
