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
 * Radiotap Flags field. Properties of transmitted and received frames.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Flags">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataFlags implements RadiotapData {

  /** */
  private static final long serialVersionUID = 3144457914168529098L;

  private static final int LENGTH = 1;

  private final boolean cfp;
  private final boolean shortPreamble;
  private final boolean wepEncrypted;
  private final boolean fragmented;
  private final boolean includingFcs;
  private final boolean padding;
  private final boolean badFcs;
  private final boolean shortGuardInterval;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapFlags object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataFlags newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataFlags(rawData, offset, length);
  }

  private RadiotapDataFlags(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 1) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapFlags (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.cfp = (rawData[offset] & 0x01) != 0;
    this.shortPreamble = (rawData[offset] & 0x02) != 0;
    this.wepEncrypted = (rawData[offset] & 0x04) != 0;
    this.fragmented = (rawData[offset] & 0x08) != 0;
    this.includingFcs = (rawData[offset] & 0x10) != 0;
    this.padding = (rawData[offset] & 0x20) != 0;
    this.badFcs = (rawData[offset] & 0x40) != 0;
    this.shortGuardInterval = (rawData[offset] & 0x80) != 0;
  }

  private RadiotapDataFlags(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.cfp = builder.cfp;
    this.shortPreamble = builder.shortPreamble;
    this.wepEncrypted = builder.wepEncrypted;
    this.fragmented = builder.fragmented;
    this.includingFcs = builder.includingFcs;
    this.padding = builder.padding;
    this.badFcs = builder.badFcs;
    this.shortGuardInterval = builder.shortGuardInterval;
  }

  /** @return cfp */
  public boolean isCfp() {
    return cfp;
  }

  /** @return shortPreamble */
  public boolean isShortPreamble() {
    return shortPreamble;
  }

  /** @return wepEncrypted */
  public boolean isWepEncrypted() {
    return wepEncrypted;
  }

  /** @return fragmented */
  public boolean isFragmented() {
    return fragmented;
  }

  /** @return includingFcs */
  public boolean isIncludingFcs() {
    return includingFcs;
  }

  /** @return padding */
  public boolean hasPadding() {
    return padding;
  }

  /** @return badFcs */
  public boolean isBadFcs() {
    return badFcs;
  }

  /** @return shortGuardInterval */
  public boolean isShortGuardInterval() {
    return shortGuardInterval;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[1];
    if (cfp) {
      data[0] |= 0x01;
    }
    if (shortPreamble) {
      data[0] |= 0x02;
    }
    if (wepEncrypted) {
      data[0] |= 0x04;
    }
    if (fragmented) {
      data[0] |= 0x08;
    }
    if (includingFcs) {
      data[0] |= 0x10;
    }
    if (padding) {
      data[0] |= 0x20;
    }
    if (badFcs) {
      data[0] |= 0x40;
    }
    if (shortGuardInterval) {
      data[0] |= 0x80;
    }
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
        .append("Flags: ")
        .append(ls)
        .append(indent)
        .append("  CFP: ")
        .append(cfp)
        .append(ls)
        .append(indent)
        .append("  Short Preamble: ")
        .append(shortPreamble)
        .append(ls)
        .append(indent)
        .append("  WEP: ")
        .append(wepEncrypted)
        .append(ls)
        .append(indent)
        .append("  Fragmented: ")
        .append(fragmented)
        .append(ls)
        .append(indent)
        .append("  FCS: ")
        .append(includingFcs)
        .append(ls)
        .append(indent)
        .append("  PAD: ")
        .append(padding)
        .append(ls)
        .append(indent)
        .append("  Bad FCS: ")
        .append(badFcs)
        .append(ls)
        .append(indent)
        .append("  Short Guard Interval: ")
        .append(shortGuardInterval)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (badFcs ? 1231 : 1237);
    result = prime * result + (cfp ? 1231 : 1237);
    result = prime * result + (fragmented ? 1231 : 1237);
    result = prime * result + (includingFcs ? 1231 : 1237);
    result = prime * result + (padding ? 1231 : 1237);
    result = prime * result + (shortGuardInterval ? 1231 : 1237);
    result = prime * result + (shortPreamble ? 1231 : 1237);
    result = prime * result + (wepEncrypted ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataFlags other = (RadiotapDataFlags) obj;
    if (badFcs != other.badFcs) return false;
    if (cfp != other.cfp) return false;
    if (fragmented != other.fragmented) return false;
    if (includingFcs != other.includingFcs) return false;
    if (padding != other.padding) return false;
    if (shortGuardInterval != other.shortGuardInterval) return false;
    if (shortPreamble != other.shortPreamble) return false;
    if (wepEncrypted != other.wepEncrypted) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private boolean cfp;
    private boolean shortPreamble;
    private boolean wepEncrypted;
    private boolean fragmented;
    private boolean includingFcs;
    private boolean padding;
    private boolean badFcs;
    private boolean shortGuardInterval;

    /** */
    public Builder() {}

    private Builder(RadiotapDataFlags obj) {
      this.cfp = obj.cfp;
    }

    /**
     * @param cfp cfp
     * @return this Builder object for method chaining.
     */
    public Builder cfp(boolean cfp) {
      this.cfp = cfp;
      return this;
    }

    /**
     * @param shortPreamble shortPreamble
     * @return this Builder object for method chaining.
     */
    public Builder shortPreamble(boolean shortPreamble) {
      this.shortPreamble = shortPreamble;
      return this;
    }

    /**
     * @param wepEncrypted wepEncrypted
     * @return this Builder object for method chaining.
     */
    public Builder wepEncrypted(boolean wepEncrypted) {
      this.wepEncrypted = wepEncrypted;
      return this;
    }

    /**
     * @param fragmented fragmented
     * @return this Builder object for method chaining.
     */
    public Builder fragmented(boolean fragmented) {
      this.fragmented = fragmented;
      return this;
    }

    /**
     * @param includingFcs includingFcs
     * @return this Builder object for method chaining.
     */
    public Builder includingFcs(boolean includingFcs) {
      this.includingFcs = includingFcs;
      return this;
    }

    /**
     * @param padding padding
     * @return this Builder object for method chaining.
     */
    public Builder padding(boolean padding) {
      this.padding = padding;
      return this;
    }

    /**
     * @param badFcs badFcs
     * @return this Builder object for method chaining.
     */
    public Builder badFcs(boolean badFcs) {
      this.badFcs = badFcs;
      return this;
    }

    /**
     * @param shortGuardInterval shortGuardInterval
     * @return this Builder object for method chaining.
     */
    public Builder shortGuardInterval(boolean shortGuardInterval) {
      this.shortGuardInterval = shortGuardInterval;
      return this;
    }

    /** @return a new RadiotapFlags object. */
    public RadiotapDataFlags build() {
      return new RadiotapDataFlags(this);
    }
  }
}
