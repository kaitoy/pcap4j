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
 * Radiotap RX flags field. Properties of received frames.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/RX%20flags">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataRxFlags implements RadiotapData {

  /** */
  private static final long serialVersionUID = -1269108995049803687L;

  private static final int LENGTH = 2;

  private final boolean lsb;
  private final boolean badPlcpCrc;
  private final boolean thirdLsb;
  private final boolean fourthLsb;
  private final boolean fifthLsb;
  private final boolean sixthLsb;
  private final boolean seventhLsb;
  private final boolean eighthLsb;
  private final boolean ninthLsb;
  private final boolean tenthLsb;
  private final boolean eleventhLsb;
  private final boolean twelvethLsb;
  private final boolean thirteenthLsb;
  private final boolean fourteenthLsb;
  private final boolean fifteenthLsb;
  private final boolean sixteenthLsb;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapRxFlags object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataRxFlags newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataRxFlags(rawData, offset, length);
  }

  private RadiotapDataRxFlags(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapRxFlags (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.lsb = (rawData[offset] & 0x01) != 0;
    this.badPlcpCrc = (rawData[offset] & 0x02) != 0;
    this.thirdLsb = (rawData[offset] & 0x04) != 0;
    this.fourthLsb = (rawData[offset] & 0x08) != 0;
    this.fifthLsb = (rawData[offset] & 0x10) != 0;
    this.sixthLsb = (rawData[offset] & 0x20) != 0;
    this.seventhLsb = (rawData[offset] & 0x40) != 0;
    this.eighthLsb = (rawData[offset] & 0x80) != 0;
    this.ninthLsb = (rawData[offset + 1] & 0x01) != 0;
    this.tenthLsb = (rawData[offset + 1] & 0x02) != 0;
    this.eleventhLsb = (rawData[offset + 1] & 0x04) != 0;
    this.twelvethLsb = (rawData[offset + 1] & 0x08) != 0;
    this.thirteenthLsb = (rawData[offset + 1] & 0x10) != 0;
    this.fourteenthLsb = (rawData[offset + 1] & 0x20) != 0;
    this.fifteenthLsb = (rawData[offset + 1] & 0x40) != 0;
    this.sixteenthLsb = (rawData[offset + 1] & 0x80) != 0;
  }

  private RadiotapDataRxFlags(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.lsb = builder.lsb;
    this.badPlcpCrc = builder.badPlcpCrc;
    this.thirdLsb = builder.thirdLsb;
    this.fourthLsb = builder.fourthLsb;
    this.fifthLsb = builder.fifthLsb;
    this.sixthLsb = builder.sixthLsb;
    this.seventhLsb = builder.seventhLsb;
    this.eighthLsb = builder.eighthLsb;
    this.ninthLsb = builder.ninthLsb;
    this.tenthLsb = builder.tenthLsb;
    this.eleventhLsb = builder.eleventhLsb;
    this.twelvethLsb = builder.twelvethLsb;
    this.thirteenthLsb = builder.thirteenthLsb;
    this.fourteenthLsb = builder.fourteenthLsb;
    this.fifteenthLsb = builder.fifteenthLsb;
    this.sixteenthLsb = builder.sixteenthLsb;
  }

  /** @return true if the LSB is set to 1; otherwise false. */
  public boolean getLsb() {
    return lsb;
  }

  /** @return badPlcpCrc */
  public boolean isBadPlcpCrc() {
    return badPlcpCrc;
  }

  /** @return true if the third LSB is set to 1; otherwise false. */
  public boolean getThirdLsb() {
    return thirdLsb;
  }

  /** @return true if the fourth LSB is set to 1; otherwise false. */
  public boolean getFourthLsb() {
    return fourthLsb;
  }

  /** @return true if the fifth LSB is set to 1; otherwise false. */
  public boolean getFifthLsb() {
    return fifthLsb;
  }

  /** @return true if the sixth LSB is set to 1; otherwise false. */
  public boolean getSixthLsb() {
    return sixthLsb;
  }

  /** @return true if the seventh LSB is set to 1; otherwise false. */
  public boolean getSeventhLsb() {
    return seventhLsb;
  }

  /** @return true if the eighth LSB is set to 1; otherwise false. */
  public boolean getEighthLsb() {
    return eighthLsb;
  }

  /** @return true if the ninth LSB is set to 1; otherwise false. */
  public boolean getNinthLsb() {
    return ninthLsb;
  }

  /** @return true if the tenth LSB is set to 1; otherwise false. */
  public boolean getTenthLsb() {
    return tenthLsb;
  }

  /** @return true if the eleventh LSB is set to 1; otherwise false. */
  public boolean getEleventhLsb() {
    return eleventhLsb;
  }

  /** @return true if the twelveth LSB is set to 1; otherwise false. */
  public boolean getTwelvethLsb() {
    return twelvethLsb;
  }

  /** @return true if the thirteenth LSB is set to 1; otherwise false. */
  public boolean getThirteenthLsb() {
    return thirteenthLsb;
  }

  /** @return true if the fourteenth LSB is set to 1; otherwise false. */
  public boolean getFourteenthLsb() {
    return fourteenthLsb;
  }

  /** @return true if the fifteenth LSB is set to 1; otherwise false. */
  public boolean getFifteenthLsb() {
    return fifteenthLsb;
  }

  /** @return true if the sixteenth LSB is set to 1; otherwise false. */
  public boolean getSixteenthLsb() {
    return sixteenthLsb;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[2];
    if (lsb) {
      data[0] |= 0x01;
    }
    if (badPlcpCrc) {
      data[0] |= 0x02;
    }
    if (thirdLsb) {
      data[0] |= 0x04;
    }
    if (fourthLsb) {
      data[0] |= 0x08;
    }
    if (fifthLsb) {
      data[0] |= 0x10;
    }
    if (sixthLsb) {
      data[0] |= 0x20;
    }
    if (seventhLsb) {
      data[0] |= 0x40;
    }
    if (eighthLsb) {
      data[0] |= 0x80;
    }
    if (ninthLsb) {
      data[1] |= 0x01;
    }
    if (tenthLsb) {
      data[1] |= 0x02;
    }
    if (eleventhLsb) {
      data[1] |= 0x04;
    }
    if (twelvethLsb) {
      data[1] |= 0x08;
    }
    if (thirteenthLsb) {
      data[1] |= 0x10;
    }
    if (fourteenthLsb) {
      data[1] |= 0x20;
    }
    if (fifteenthLsb) {
      data[1] |= 0x40;
    }
    if (sixteenthLsb) {
      data[1] |= 0x80;
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
        .append("RX flags: ")
        .append(ls)
        .append(indent)
        .append("  LSB: ")
        .append(lsb)
        .append(ls)
        .append(indent)
        .append("  Bad PLCP CRC: ")
        .append(badPlcpCrc)
        .append(ls)
        .append(indent)
        .append("  3rd LSB: ")
        .append(thirdLsb)
        .append(ls)
        .append(indent)
        .append("  4th LSB: ")
        .append(fourthLsb)
        .append(ls)
        .append(indent)
        .append("  5th LSB: ")
        .append(fifthLsb)
        .append(ls)
        .append(indent)
        .append("  6th LSB: ")
        .append(sixthLsb)
        .append(ls)
        .append(indent)
        .append("  7th LSB: ")
        .append(seventhLsb)
        .append(ls)
        .append(indent)
        .append("  8th LSB: ")
        .append(eighthLsb)
        .append(ls)
        .append(indent)
        .append("  9th LSB: ")
        .append(ninthLsb)
        .append(ls)
        .append(indent)
        .append("  10th LSB: ")
        .append(tenthLsb)
        .append(ls)
        .append(indent)
        .append("  11th LSB: ")
        .append(eleventhLsb)
        .append(ls)
        .append(indent)
        .append("  12th LSB: ")
        .append(twelvethLsb)
        .append(ls)
        .append(indent)
        .append("  13th LSB: ")
        .append(thirteenthLsb)
        .append(ls)
        .append(indent)
        .append("  14th LSB: ")
        .append(fourteenthLsb)
        .append(ls)
        .append(indent)
        .append("  15th LSB: ")
        .append(fifteenthLsb)
        .append(ls)
        .append(indent)
        .append("  16th LSB: ")
        .append(sixteenthLsb)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (sixthLsb ? 1231 : 1237);
    result = prime * result + (eleventhLsb ? 1231 : 1237);
    result = prime * result + (ninthLsb ? 1231 : 1237);
    result = prime * result + (fourthLsb ? 1231 : 1237);
    result = prime * result + (twelvethLsb ? 1231 : 1237);
    result = prime * result + (thirteenthLsb ? 1231 : 1237);
    result = prime * result + (fifteenthLsb ? 1231 : 1237);
    result = prime * result + (lsb ? 1231 : 1237);
    result = prime * result + (seventhLsb ? 1231 : 1237);
    result = prime * result + (tenthLsb ? 1231 : 1237);
    result = prime * result + (sixteenthLsb ? 1231 : 1237);
    result = prime * result + (badPlcpCrc ? 1231 : 1237);
    result = prime * result + (fourteenthLsb ? 1231 : 1237);
    result = prime * result + (thirdLsb ? 1231 : 1237);
    result = prime * result + (fifthLsb ? 1231 : 1237);
    result = prime * result + (eighthLsb ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataRxFlags other = (RadiotapDataRxFlags) obj;
    if (sixthLsb != other.sixthLsb) return false;
    if (eleventhLsb != other.eleventhLsb) return false;
    if (ninthLsb != other.ninthLsb) return false;
    if (fourthLsb != other.fourthLsb) return false;
    if (twelvethLsb != other.twelvethLsb) return false;
    if (thirteenthLsb != other.thirteenthLsb) return false;
    if (fifteenthLsb != other.fifteenthLsb) return false;
    if (lsb != other.lsb) return false;
    if (seventhLsb != other.seventhLsb) return false;
    if (tenthLsb != other.tenthLsb) return false;
    if (sixteenthLsb != other.sixteenthLsb) return false;
    if (badPlcpCrc != other.badPlcpCrc) return false;
    if (fourteenthLsb != other.fourteenthLsb) return false;
    if (thirdLsb != other.thirdLsb) return false;
    if (fifthLsb != other.fifthLsb) return false;
    if (eighthLsb != other.eighthLsb) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private boolean lsb;
    private boolean badPlcpCrc;
    private boolean thirdLsb;
    private boolean fourthLsb;
    private boolean fifthLsb;
    private boolean sixthLsb;
    private boolean seventhLsb;
    private boolean eighthLsb;
    private boolean ninthLsb;
    private boolean tenthLsb;
    private boolean eleventhLsb;
    private boolean twelvethLsb;
    private boolean thirteenthLsb;
    private boolean fourteenthLsb;
    private boolean fifteenthLsb;
    private boolean sixteenthLsb;

    /** */
    public Builder() {}

    private Builder(RadiotapDataRxFlags obj) {
      this.lsb = obj.lsb;
      this.badPlcpCrc = obj.badPlcpCrc;
      this.thirdLsb = obj.thirdLsb;
      this.fourthLsb = obj.fourthLsb;
      this.fifthLsb = obj.fifthLsb;
      this.sixthLsb = obj.sixthLsb;
      this.seventhLsb = obj.seventhLsb;
      this.eighthLsb = obj.eighthLsb;
      this.ninthLsb = obj.ninthLsb;
      this.tenthLsb = obj.tenthLsb;
      this.eleventhLsb = obj.eleventhLsb;
      this.twelvethLsb = obj.twelvethLsb;
      this.thirteenthLsb = obj.thirteenthLsb;
      this.fourteenthLsb = obj.fourteenthLsb;
      this.fifteenthLsb = obj.fifteenthLsb;
      this.sixteenthLsb = obj.sixteenthLsb;
    }

    /**
     * @param lsb lsb
     * @return this Builder object for method chaining.
     */
    public Builder lsb(boolean lsb) {
      this.lsb = lsb;
      return this;
    }

    /**
     * @param badPlcpCrc badPlcpCrc
     * @return this Builder object for method chaining.
     */
    public Builder badPlcpCrc(boolean badPlcpCrc) {
      this.badPlcpCrc = badPlcpCrc;
      return this;
    }

    /**
     * @param thirdLsb thirdLsb
     * @return this Builder object for method chaining.
     */
    public Builder thirdLsb(boolean thirdLsb) {
      this.thirdLsb = thirdLsb;
      return this;
    }

    /**
     * @param fourthLsb fourthLsb
     * @return this Builder object for method chaining.
     */
    public Builder fourthLsb(boolean fourthLsb) {
      this.fourthLsb = fourthLsb;
      return this;
    }

    /**
     * @param fifthLsb fifthLsb
     * @return this Builder object for method chaining.
     */
    public Builder fifthLsb(boolean fifthLsb) {
      this.fifthLsb = fifthLsb;
      return this;
    }

    /**
     * @param sixthLsb sixthLsb
     * @return this Builder object for method chaining.
     */
    public Builder sixthLsb(boolean sixthLsb) {
      this.sixthLsb = sixthLsb;
      return this;
    }

    /**
     * @param seventhLsb seventhLsb
     * @return this Builder object for method chaining.
     */
    public Builder seventhLsb(boolean seventhLsb) {
      this.seventhLsb = seventhLsb;
      return this;
    }

    /**
     * @param eighthLsb eighthLsb
     * @return this Builder object for method chaining.
     */
    public Builder eighthLsb(boolean eighthLsb) {
      this.eighthLsb = eighthLsb;
      return this;
    }

    /**
     * @param ninthLsb ninthLsb
     * @return this Builder object for method chaining.
     */
    public Builder ninthLsb(boolean ninthLsb) {
      this.ninthLsb = ninthLsb;
      return this;
    }

    /**
     * @param tenthLsb tenthLsb
     * @return this Builder object for method chaining.
     */
    public Builder tenthLsb(boolean tenthLsb) {
      this.tenthLsb = tenthLsb;
      return this;
    }

    /**
     * @param eleventhLsb eleventhLsb
     * @return this Builder object for method chaining.
     */
    public Builder eleventhLsb(boolean eleventhLsb) {
      this.eleventhLsb = eleventhLsb;
      return this;
    }

    /**
     * @param twelvethLsb twelvethLsb
     * @return this Builder object for method chaining.
     */
    public Builder twelvethLsb(boolean twelvethLsb) {
      this.twelvethLsb = twelvethLsb;
      return this;
    }

    /**
     * @param thirteenthLsb thirteenthLsb
     * @return this Builder object for method chaining.
     */
    public Builder thirteenthLsb(boolean thirteenthLsb) {
      this.thirteenthLsb = thirteenthLsb;
      return this;
    }

    /**
     * @param fourteenthLsb fourteenthLsb
     * @return this Builder object for method chaining.
     */
    public Builder fourteenthLsb(boolean fourteenthLsb) {
      this.fourteenthLsb = fourteenthLsb;
      return this;
    }

    /**
     * @param fifteenthLsb fifteenthLsb
     * @return this Builder object for method chaining.
     */
    public Builder fifteenthLsb(boolean fifteenthLsb) {
      this.fifteenthLsb = fifteenthLsb;
      return this;
    }

    /**
     * @param sixteenthLsb sixteenthLsb
     * @return this Builder object for method chaining.
     */
    public Builder sixteenthLsb(boolean sixteenthLsb) {
      this.sixteenthLsb = sixteenthLsb;
      return this;
    }

    /** @return a new RadiotapRxFlags object. */
    public RadiotapDataRxFlags build() {
      return new RadiotapDataRxFlags(this);
    }
  }
}
