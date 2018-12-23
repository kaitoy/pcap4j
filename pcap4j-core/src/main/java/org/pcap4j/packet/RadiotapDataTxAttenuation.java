/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.nio.ByteOrder;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap TX attenuation field. Transmit power expressed as unitless distance from max power set
 * at factory calibration. 0 is max power. Monotonically nondecreasing with lower power levels.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/TX%20attenuation">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataTxAttenuation implements RadiotapData {

  /** */
  private static final long serialVersionUID = 8847948493831117966L;

  private static final int LENGTH = 2;

  private final short txAttenuation;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapTxAttenuation object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataTxAttenuation newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataTxAttenuation(rawData, offset, length);
  }

  private RadiotapDataTxAttenuation(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapTxAttenuation (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.txAttenuation = ByteArrays.getShort(rawData, offset, ByteOrder.LITTLE_ENDIAN);
  }

  private RadiotapDataTxAttenuation(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.txAttenuation = builder.txAttenuation;
  }

  /** @return txAttenuation */
  public short getTxAttenuation() {
    return txAttenuation;
  }

  /** @return txAttenuation */
  public int getTxAttenuationAsInt() {
    return txAttenuation & 0xFFFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(txAttenuation, ByteOrder.LITTLE_ENDIAN);
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
        .append("TX attenuation: ")
        .append(ls)
        .append(indent)
        .append("  TX attenuation: ")
        .append(getTxAttenuationAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return txAttenuation;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataTxAttenuation other = (RadiotapDataTxAttenuation) obj;
    return txAttenuation == other.txAttenuation;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private short txAttenuation;

    /** */
    public Builder() {}

    private Builder(RadiotapDataTxAttenuation obj) {
      this.txAttenuation = obj.txAttenuation;
    }

    /**
     * @param txAttenuation txAttenuation
     * @return this Builder object for method chaining.
     */
    public Builder txAttenuation(short txAttenuation) {
      this.txAttenuation = txAttenuation;
      return this;
    }

    /** @return a new RadiotapTxAttenuation object. */
    public RadiotapDataTxAttenuation build() {
      return new RadiotapDataTxAttenuation(this);
    }
  }
}
