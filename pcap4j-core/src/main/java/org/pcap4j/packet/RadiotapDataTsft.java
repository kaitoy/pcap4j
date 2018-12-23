/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.math.BigInteger;
import java.nio.ByteOrder;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap TSFT field. Value in microseconds of the MAC's 64-bit 802.11 Time Synchronization
 * Function timer when the first bit of the MPDU arrived at the MAC. For received frames only.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/TSFT">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataTsft implements RadiotapData {

  /** */
  private static final long serialVersionUID = -6492811566937170319L;

  private static final int LENGTH = 8;

  private final BigInteger macTimestamp;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapTsft object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataTsft newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataTsft(rawData, offset, length);
  }

  private RadiotapDataTsft(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapTsft (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.macTimestamp =
        new BigInteger(
            new byte[] {
              (byte) 0,
              rawData[offset + 7],
              rawData[offset + 6],
              rawData[offset + 5],
              rawData[offset + 4],
              rawData[offset + 3],
              rawData[offset + 2],
              rawData[offset + 1],
              rawData[offset + 0],
            });
  }

  private RadiotapDataTsft(Builder builder) {
    if (builder == null || builder.macTimestamp == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.macTimestamp: ")
          .append(builder.macTimestamp);
      throw new NullPointerException(sb.toString());
    }
    if (builder.macTimestamp.signum() == -1) {
      throw new IllegalArgumentException("macTimestamp must be positive.");
    }
    if (builder.macTimestamp.bitLength() > LENGTH * ByteArrays.BYTE_SIZE_IN_BITS) {
      throw new IllegalArgumentException("macTimestamp must be less than 18446744073709551616.");
    }

    this.macTimestamp = builder.macTimestamp;
  }

  /** @return macTimestamp (unit: microseconds) */
  public BigInteger getMacTimestamp() {
    return macTimestamp;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(macTimestamp.longValue(), ByteOrder.LITTLE_ENDIAN);
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
        .append("TSFT: ")
        .append(ls)
        .append(indent)
        .append("  MAC timestamp: ")
        .append(macTimestamp)
        .append(" microseconds")
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return macTimestamp.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataTsft other = (RadiotapDataTsft) obj;
    return macTimestamp.equals(other.macTimestamp);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private BigInteger macTimestamp;

    /** */
    public Builder() {}

    private Builder(RadiotapDataTsft obj) {
      this.macTimestamp = obj.macTimestamp;
    }

    /**
     * @param macTimestamp macTimestamp
     * @return this Builder object for method chaining.
     */
    public Builder macTimestamp(BigInteger macTimestamp) {
      this.macTimestamp = macTimestamp;
      return this;
    }

    /** @return a new RadiotapTsft object. */
    public RadiotapDataTsft build() {
      return new RadiotapDataTsft(this);
    }
  }
}
