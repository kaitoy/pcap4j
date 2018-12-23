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
 * Radiotap Antenna field. Unitless indication of the Rx/Tx antenna for this packet. The first
 * antenna is antenna 0.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Antenna">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataAntenna implements RadiotapData {

  /** */
  private static final long serialVersionUID = -4959721095331063491L;

  private static final int LENGTH = 1;

  private final byte antenna;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapRate object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataAntenna newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataAntenna(rawData, offset, length);
  }

  private RadiotapDataAntenna(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapRate (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.antenna = ByteArrays.getByte(rawData, offset);
  }

  private RadiotapDataAntenna(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.antenna = builder.antenna;
  }

  /** @return antenna */
  public byte getAntenna() {
    return antenna;
  }

  /** @return antenna */
  public int getAntennaAsInt() {
    return antenna & 0xFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(antenna);
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
        .append("Antenna: ")
        .append(ls)
        .append(indent)
        .append("  Antenna: ")
        .append(getAntennaAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return antenna;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataAntenna other = (RadiotapDataAntenna) obj;
    return antenna == other.antenna;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte antenna;

    /** */
    public Builder() {}

    private Builder(RadiotapDataAntenna obj) {
      this.antenna = obj.antenna;
    }

    /**
     * @param antenna antenna
     * @return this Builder object for method chaining.
     */
    public Builder antenna(byte antenna) {
      this.antenna = antenna;
      return this;
    }

    /** @return a new RadiotapRate object. */
    public RadiotapDataAntenna build() {
      return new RadiotapDataAntenna(this);
    }
  }
}
