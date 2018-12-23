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
 * Radiotap Rate field. TX/RX data rate.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Rate">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataRate implements RadiotapData {

  /** */
  private static final long serialVersionUID = 3381222627210403160L;

  private static final int LENGTH = 1;

  private final byte rate;

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
  public static RadiotapDataRate newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataRate(rawData, offset, length);
  }

  private RadiotapDataRate(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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

    this.rate = ByteArrays.getByte(rawData, offset);
  }

  private RadiotapDataRate(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.rate = builder.rate;
  }

  /** @return rate (unit: 500 Kbps) */
  public byte getRate() {
    return rate;
  }

  /** @return rate (unit: 500 Kbps) */
  public int getRateAsInt() {
    return rate & 0xFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(rate);
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
        .append("Rate: ")
        .append(ls)
        .append(indent)
        .append("  Rate: ")
        .append(getRateAsInt() * 500)
        .append(" Kbps")
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return rate;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataRate other = (RadiotapDataRate) obj;
    return rate == other.rate;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte rate;

    /** */
    public Builder() {}

    private Builder(RadiotapDataRate obj) {
      this.rate = obj.rate;
    }

    /**
     * @param rate rate
     * @return this Builder object for method chaining.
     */
    public Builder rate(byte rate) {
      this.rate = rate;
      return this;
    }

    /** @return a new RadiotapRate object. */
    public RadiotapDataRate build() {
      return new RadiotapDataRate(this);
    }
  }
}
