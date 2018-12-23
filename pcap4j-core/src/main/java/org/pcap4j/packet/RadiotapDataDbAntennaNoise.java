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
 * Radiotap dB antenna noise field. RF noise power at the antenna, decibel difference from an
 * arbitrary, fixed reference. This field contains a single unsigned 8-bit value.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/dB%20antenna%20noise">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataDbAntennaNoise implements RadiotapData {

  /** */
  private static final long serialVersionUID = 3285930614145918404L;

  private static final int LENGTH = 1;

  private final byte antennaNoise;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapDbAntennaNoise object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataDbAntennaNoise newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataDbAntennaNoise(rawData, offset, length);
  }

  private RadiotapDataDbAntennaNoise(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapDbAntennaNoise (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.antennaNoise = ByteArrays.getByte(rawData, offset);
  }

  private RadiotapDataDbAntennaNoise(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.antennaNoise = builder.antennaNoise;
  }

  /** @return antennaNoise (unit: dB) */
  public byte getAntennaNoise() {
    return antennaNoise;
  }

  /** @return antennaNoise (unit: dB) */
  public int getAntennaNoiseAsInt() {
    return antennaNoise & 0xFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(antennaNoise);
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
        .append("dB antenna noise: ")
        .append(ls)
        .append(indent)
        .append("  Antenna noise: ")
        .append(getAntennaNoiseAsInt())
        .append(" dB")
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return antennaNoise;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataDbAntennaNoise other = (RadiotapDataDbAntennaNoise) obj;
    return antennaNoise == other.antennaNoise;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte antennaNoise;

    /** */
    public Builder() {}

    private Builder(RadiotapDataDbAntennaNoise obj) {
      this.antennaNoise = obj.antennaNoise;
    }

    /**
     * @param antennaNoise antennaNoise
     * @return this Builder object for method chaining.
     */
    public Builder antennaNoise(byte antennaNoise) {
      this.antennaNoise = antennaNoise;
      return this;
    }

    /** @return a new RadiotapDbAntennaNoise object. */
    public RadiotapDataDbAntennaNoise build() {
      return new RadiotapDataDbAntennaNoise(this);
    }
  }
}
