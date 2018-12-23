/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.util.ByteArrays;

/**
 * Pad between Radiotap fields.
 *
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataPad implements RadiotapData {

  /** */
  private static final long serialVersionUID = 2443487622598511815L;

  private final byte[] pad;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param pad pad
   * @param offset offset
   * @param length length
   * @return a new RadiotapDataPad object.
   */
  public static RadiotapDataPad newInstance(byte[] pad, int offset, int length) {
    ByteArrays.validateBounds(pad, offset, length);
    return new RadiotapDataPad(pad, offset, length);
  }

  private RadiotapDataPad(byte[] pad, int offset, int length) {
    this.pad = ByteArrays.getSubArray(pad, offset, length);
  }

  private RadiotapDataPad(Builder builder) {
    if (builder == null || builder.pad == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.pad: ").append(builder.pad);
      throw new NullPointerException(sb.toString());
    }

    this.pad = ByteArrays.clone(builder.pad);
  }

  @Override
  public int length() {
    return pad.length;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.clone(pad);
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
        .append("Pad: ")
        .append(ls)
        .append(indent)
        .append("  data: ")
        .append(ByteArrays.toHexString(pad, " "))
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(pad);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    RadiotapDataPad other = (RadiotapDataPad) obj;
    return Arrays.equals(pad, other.pad);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte[] pad;

    /** */
    public Builder() {}

    private Builder(RadiotapDataPad obj) {
      this.pad = obj.pad;
    }

    /**
     * @param pad pad
     * @return this Builder object for method chaining.
     */
    public Builder pad(byte[] pad) {
      this.pad = pad;
      return this;
    }

    /** @return a new RadiotapDataPad object. */
    public RadiotapDataPad build() {
      return new RadiotapDataPad(this);
    }
  }
}
