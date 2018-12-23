/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.ByteArrays;

/**
 * DNS WKS RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ADDRESS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |       PROTOCOL        |                       |
 * +--+--+--+--+--+--+--+--+                       |
 * |                                               |
 * /                   &lt;BIT MAP&gt;                   /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * ADDRESS         An 32 bit Internet address
 *
 * PROTOCOL        An 8 bit IP protocol number
 *
 * &lt;BIT MAP&gt;       A variable length bit map.  The bit map must be a
 *                 multiple of 8 bits long.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataWks implements DnsRData {

  /** */
  private static final long serialVersionUID = 4550031993619542554L;

  private final Inet4Address address;
  private final IpNumber protocol;
  private final byte[] bitMap;
  private final List<Integer> portNumbers;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataWks object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataWks newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataWks(rawData, offset, length);
  }

  private DnsRDataWks(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < INET4_ADDRESS_SIZE_IN_BYTES + BYTE_SIZE_IN_BYTES) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a DnsRDataWks (")
          .append(INET4_ADDRESS_SIZE_IN_BYTES + BYTE_SIZE_IN_BYTES)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    int cursor = 0;
    this.address = ByteArrays.getInet4Address(rawData, offset);
    cursor += INET4_ADDRESS_SIZE_IN_BYTES;

    this.protocol = IpNumber.getInstance(ByteArrays.getByte(rawData, offset + cursor));
    cursor += BYTE_SIZE_IN_BYTES;

    if (cursor < length) {
      this.bitMap = ByteArrays.getSubArray(rawData, offset + cursor, length - cursor);
    } else {
      this.bitMap = new byte[0];
    }

    if (bitMap.length > 8192) {
      throw new IllegalRawDataException(
          "Length of bitMap must be less than 8193. bitMap.length: " + bitMap.length);
    }

    this.portNumbers = toPortNumbers(bitMap);
  }

  private DnsRDataWks(Builder builder) {
    if (builder == null || builder.address == null || builder.protocol == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.address: ")
          .append(builder.address)
          .append(" builder.protocol: ")
          .append(builder.protocol);
      throw new NullPointerException(sb.toString());
    }

    this.address = builder.address;
    this.protocol = builder.protocol;

    if (builder.bitMap != null) {
      if (builder.bitMap.length > 8192) {
        throw new IllegalArgumentException(
            "Length of bitMap must be less than 8193. builder.bitMap.length: "
                + builder.bitMap.length);
      }
      this.bitMap = ByteArrays.clone(builder.bitMap);
      this.portNumbers = toPortNumbers(bitMap);
    } else if (builder.portNumbers != null) {
      this.portNumbers = new ArrayList<Integer>(builder.portNumbers);
      if (portNumbers.size() != 0) {
        Collections.sort(portNumbers);
        int lastIdx = portNumbers.size() - 1;
        int maxPortNum = portNumbers.get(lastIdx);
        if ((maxPortNum & 0xFFFF0000) != 0) {
          throw new IllegalArgumentException(
              "(port & 0xFFFF0000) must be zero. port: " + maxPortNum);
        }

        this.bitMap = new byte[maxPortNum / 8 + 1];
        for (int num : portNumbers) {
          bitMap[num / 8] |= 0x80 >> num % 8;
        }
      } else {
        this.bitMap = new byte[0];
      }
    } else {
      throw new NullPointerException("Both bitMap and portNumbers are null.");
    }
  }

  private List<Integer> toPortNumbers(byte[] bitMap) {
    List<Integer> portNums = new ArrayList<Integer>();
    int portNum = 0;
    for (byte octet : bitMap) {
      for (int numShifts = 7; numShifts >= 0; numShifts--, portNum++) {
        if (((octet >> numShifts) & 1) != 0) {
          portNums.add(portNum);
        }
      }
    }
    return portNums;
  }

  /** @return address */
  public Inet4Address getAddress() {
    return address;
  }

  /** @return protocol */
  public IpNumber getProtocol() {
    return protocol;
  }

  /**
   * @return bitMap. Another view of portNumbers.
   * @see #getPortNumbers()
   */
  public byte[] getBitMap() {
    return ByteArrays.clone(bitMap);
  }

  /**
   * @return portNumbers. Another view of bitMap.
   * @see #getBitMap()
   */
  public List<Integer> getPortNumbers() {
    return new ArrayList<Integer>(portNumbers);
  }

  @Override
  public int length() {
    return INET4_ADDRESS_SIZE_IN_BYTES + BYTE_SIZE_IN_BYTES + bitMap.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;

    System.arraycopy(address.getAddress(), 0, data, cursor, INET4_ADDRESS_SIZE_IN_BYTES);
    cursor += INET4_ADDRESS_SIZE_IN_BYTES;

    System.arraycopy(ByteArrays.toByteArray(protocol.value()), 0, data, cursor, BYTE_SIZE_IN_BYTES);
    cursor += BYTE_SIZE_IN_BYTES;

    System.arraycopy(bitMap, 0, data, cursor, bitMap.length);

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
        .append("WKS RDATA:")
        .append(ls)
        .append(indent)
        .append("  ADDRESS: ")
        .append(address.getHostAddress())
        .append(ls)
        .append(indent)
        .append("  PROTOCOL: ")
        .append(protocol)
        .append(ls)
        .append(indent)
        .append("  BIT MAP: 0x")
        .append(ByteArrays.toHexString(bitMap, ""))
        .append(ls)
        .append(indent)
        .append("  PORTS: ");

    Iterator<Integer> iter = portNumbers.iterator();
    while (iter.hasNext()) {
      sb.append(iter.next());
      if (iter.hasNext()) {
        sb.append(", ");
      }
    }
    sb.append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + address.hashCode();
    result = prime * result + Arrays.hashCode(bitMap);
    result = prime * result + protocol.hashCode();
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
    DnsRDataWks other = (DnsRDataWks) obj;
    if (!address.equals(other.address)) {
      return false;
    }
    if (!Arrays.equals(bitMap, other.bitMap)) {
      return false;
    }
    if (!protocol.equals(other.protocol)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private Inet4Address address;
    private IpNumber protocol;
    private byte[] bitMap = null;
    private List<Integer> portNumbers = null;

    /** */
    public Builder() {}

    private Builder(DnsRDataWks obj) {
      this.address = obj.address;
      this.protocol = obj.protocol;
      this.bitMap = obj.bitMap;
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
     * @param protocol protocol
     * @return this Builder object for method chaining.
     */
    public Builder protocol(IpNumber protocol) {
      this.protocol = protocol;
      return this;
    }

    /**
     * Set a bitMap. If a bitMap is set by this method, the portNumbers already set is discarded.
     *
     * @param bitMap bitMap
     * @return this Builder object for method chaining.
     * @see #portNumbers(List)
     */
    public Builder bitMap(byte[] bitMap) {
      this.bitMap = bitMap;
      this.portNumbers = null;
      return this;
    }

    /**
     * Set a portNumber list. If a portNumber list is set by this method, the bitMap already set is
     * discarded.
     *
     * @param portNumbers portNumbers
     * @return this Builder object for method chaining.
     * @see #bitMap(byte[])
     */
    public Builder portNumbers(List<Integer> portNumbers) {
      this.portNumbers = portNumbers;
      this.bitMap = null;
      return this;
    }

    /** @return a new DnsRDataWks object. */
    public DnsRDataWks build() {
      return new DnsRDataWks(this);
    }
  }
}
