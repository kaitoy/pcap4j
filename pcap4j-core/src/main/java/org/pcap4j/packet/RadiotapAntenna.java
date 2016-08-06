/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.RadiotapPacket.RadiotapDataField;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap Antenna field.
 * Unitless indication of the Rx/Tx antenna for this packet.
 * The first antenna is antenna 0.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Antenna">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapAntenna implements RadiotapDataField {

  /**
   *
   */
  private static final long serialVersionUID = -4959721095331063491L;

  private static final int LENGTH = 1;

  private final byte antenna;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapRate object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapAntenna newInstance(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapAntenna(rawData, offset, length);
  }

  private RadiotapAntenna(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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

  private RadiotapAntenna(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.antenna = builder.antenna;
  }

  /**
   * @return antenna
   */
  public byte getAntenna() { return antenna; }

  /**
   * @return antenna
   */
  public int getAntennaAsInt() { return antenna & 0xFF; }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(antenna);
  }

  /**
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Antenna: ")
      .append(getAntennaAsInt())
      .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return antenna;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    RadiotapAntenna other = (RadiotapAntenna) obj;
    return antenna == other.antenna;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte antenna;

    /**
     *
     */
    public Builder() {}

    private Builder(RadiotapAntenna obj) {
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

    /**
     * @return a new RadiotapRate object.
     */
    public RadiotapAntenna build() {
      return new RadiotapAntenna(this);
    }

  }

}
