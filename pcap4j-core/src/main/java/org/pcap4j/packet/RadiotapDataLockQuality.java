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
 * Radiotap Lock quality field. Quality of Barker code lock. Unitless. Monotonically nondecreasing
 * with "better" lock strength. Called "Signal Quality" in datasheets.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Lock%20quality">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataLockQuality implements RadiotapData {

  /** */
  private static final long serialVersionUID = -7889325752343077807L;

  private static final int LENGTH = 2;

  private final short lockQuality;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapLockQuality object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataLockQuality newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataLockQuality(rawData, offset, length);
  }

  private RadiotapDataLockQuality(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapLockQuality (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.lockQuality = ByteArrays.getShort(rawData, offset, ByteOrder.LITTLE_ENDIAN);
  }

  private RadiotapDataLockQuality(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.lockQuality = builder.lockQuality;
  }

  /** @return lockQuality */
  public short getLockQuality() {
    return lockQuality;
  }

  /** @return lockQuality */
  public int getLockQualityAsInt() {
    return lockQuality & 0xFFFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.toByteArray(lockQuality, ByteOrder.LITTLE_ENDIAN);
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
        .append("Lock quality: ")
        .append(ls)
        .append(indent)
        .append("  Lock quality: ")
        .append(getLockQualityAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return lockQuality;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataLockQuality other = (RadiotapDataLockQuality) obj;
    return lockQuality == other.lockQuality;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private short lockQuality;

    /** */
    public Builder() {}

    private Builder(RadiotapDataLockQuality obj) {
      this.lockQuality = obj.lockQuality;
    }

    /**
     * @param lockQuality lockQuality
     * @return this Builder object for method chaining.
     */
    public Builder lockQuality(short lockQuality) {
      this.lockQuality = lockQuality;
      return this;
    }

    /** @return a new RadiotapLockQuality object. */
    public RadiotapDataLockQuality build() {
      return new RadiotapDataLockQuality(this);
    }
  }
}
