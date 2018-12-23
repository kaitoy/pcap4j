/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap FHSS field. The hop set and pattern for frequency-hopping radios.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/FHSS">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataFhss implements RadiotapData {

  /** */
  private static final long serialVersionUID = 132223820938643993L;

  private static final int LENGTH = 2;

  private final byte hopSet;
  private final byte hopPattern;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapFhss object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataFhss newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataFhss(rawData, offset, length);
  }

  private RadiotapDataFhss(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapFhss (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.hopSet = ByteArrays.getByte(rawData, offset);
    this.hopPattern = ByteArrays.getByte(rawData, offset + 1);
  }

  private RadiotapDataFhss(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.hopSet = builder.hopSet;
    this.hopPattern = builder.hopPattern;
  }

  /** @return hopSet */
  public byte getHopSet() {
    return hopSet;
  }

  /** @return hopSet */
  public int getHopSetAsInt() {
    return hopSet & 0xFF;
  }

  /** @return hopPattern */
  public byte getHopPattern() {
    return hopPattern;
  }

  /** @return hopPattern */
  public int getHopPatternAsInt() {
    return hopPattern & 0xFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[2];
    data[0] = hopSet;
    data[1] = hopPattern;
    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return toString("");
  }

  @Override
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("FHSS: ")
        .append(ls)
        .append(indent)
        .append("  Hop set: ")
        .append(getHopSetAsInt())
        .append(ls)
        .append(indent)
        .append("  Hop pattern: ")
        .append(getHopPatternAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + hopPattern;
    result = prime * result + hopSet;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataFhss other = (RadiotapDataFhss) obj;
    if (hopPattern != other.hopPattern) return false;
    if (hopSet != other.hopSet) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte hopSet;
    private byte hopPattern;

    /** */
    public Builder() {}

    private Builder(RadiotapDataFhss obj) {
      this.hopSet = obj.hopSet;
      this.hopPattern = obj.hopPattern;
    }

    /**
     * @param hopSet hopSet
     * @return this Builder object for method chaining.
     */
    public Builder hopSet(byte hopSet) {
      this.hopSet = hopSet;
      return this;
    }

    /**
     * @param hopPattern hopPattern
     * @return this Builder object for method chaining.
     */
    public Builder hopPattern(byte hopPattern) {
      this.hopPattern = hopPattern;
      return this;
    }

    /** @return a new RadiotapFhss object. */
    public RadiotapDataFhss build() {
      return new RadiotapDataFhss(this);
    }
  }
}
