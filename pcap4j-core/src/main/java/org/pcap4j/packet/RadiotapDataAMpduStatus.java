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
 * Radiotap A-MPDU status field.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/A-MPDU%20status">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataAMpduStatus implements RadiotapData {

  /** */
  private static final long serialVersionUID = 5595179236319330489L;

  private static final int LENGTH = 8;

  private final int referenceNumber;
  private final boolean driverReportsZeroLengthSubframes;
  private final boolean zeroLengthSubframe;
  private final boolean lastSubframeKnown;
  private final boolean lastSubframe;
  private final boolean delimiterCrcError;
  private final boolean delimiterCrcValueKnown;
  private final boolean tenthMsbOfFlags;
  private final boolean ninthMsbOfFlags;
  private final boolean eighthMsbOfFlags;
  private final boolean seventhMsbOfFlags;
  private final boolean sixthMsbOfFlags;
  private final boolean fifthMsbOfFlags;
  private final boolean fourthMsbOfFlags;
  private final boolean thirdMsbOfFlags;
  private final boolean secondMsbOfFlags;
  private final boolean msbOfFlags;
  private final byte delimiterCrcValue;
  private final byte reserved;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapAMpduStatus object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataAMpduStatus newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataAMpduStatus(rawData, offset, length);
  }

  private RadiotapDataAMpduStatus(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapAMpduStatus (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.referenceNumber = ByteArrays.getInt(rawData, offset, ByteOrder.LITTLE_ENDIAN);
    this.driverReportsZeroLengthSubframes = (rawData[offset + 4] & 0x01) != 0;
    this.zeroLengthSubframe = (rawData[offset + 4] & 0x02) != 0;
    this.lastSubframeKnown = (rawData[offset + 4] & 0x04) != 0;
    this.lastSubframe = (rawData[offset + 4] & 0x08) != 0;
    this.delimiterCrcError = (rawData[offset + 4] & 0x10) != 0;
    this.delimiterCrcValueKnown = (rawData[offset + 4] & 0x20) != 0;
    this.tenthMsbOfFlags = (rawData[offset + 4] & 0x40) != 0;
    this.ninthMsbOfFlags = (rawData[offset + 4] & 0x80) != 0;
    this.eighthMsbOfFlags = (rawData[offset + 5] & 0x01) != 0;
    this.seventhMsbOfFlags = (rawData[offset + 5] & 0x02) != 0;
    this.sixthMsbOfFlags = (rawData[offset + 5] & 0x04) != 0;
    this.fifthMsbOfFlags = (rawData[offset + 5] & 0x08) != 0;
    this.fourthMsbOfFlags = (rawData[offset + 5] & 0x10) != 0;
    this.thirdMsbOfFlags = (rawData[offset + 5] & 0x20) != 0;
    this.secondMsbOfFlags = (rawData[offset + 5] & 0x40) != 0;
    this.msbOfFlags = (rawData[offset + 5] & 0x80) != 0;
    this.delimiterCrcValue = rawData[offset + 6];
    this.reserved = rawData[offset + 7];
  }

  private RadiotapDataAMpduStatus(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.referenceNumber = builder.referenceNumber;
    this.driverReportsZeroLengthSubframes = builder.driverReportsZeroLengthSubframes;
    this.zeroLengthSubframe = builder.zeroLengthSubframe;
    this.lastSubframeKnown = builder.lastSubframeKnown;
    this.lastSubframe = builder.lastSubframe;
    this.delimiterCrcError = builder.delimiterCrcError;
    this.delimiterCrcValueKnown = builder.delimiterCrcValueKnown;
    this.tenthMsbOfFlags = builder.tenthMsbOfFlags;
    this.ninthMsbOfFlags = builder.ninthMsbOfFlags;
    this.eighthMsbOfFlags = builder.eighthMsbOfFlags;
    this.seventhMsbOfFlags = builder.seventhMsbOfFlags;
    this.sixthMsbOfFlags = builder.sixthMsbOfFlags;
    this.fifthMsbOfFlags = builder.fifthMsbOfFlags;
    this.fourthMsbOfFlags = builder.fourthMsbOfFlags;
    this.thirdMsbOfFlags = builder.thirdMsbOfFlags;
    this.secondMsbOfFlags = builder.secondMsbOfFlags;
    this.msbOfFlags = builder.msbOfFlags;
    this.delimiterCrcValue = builder.delimiterCrcValue;
    this.reserved = builder.reserved;
  }

  /** @return referenceNumber */
  public int getReferenceNumber() {
    return referenceNumber;
  }

  /** @return referenceNumber */
  public long getReferenceNumberAsLong() {
    return referenceNumber & 0xFFFFFFFFL;
  }

  /** @return true if the driver reports 0-length subframes; false otherwise. */
  public boolean getDriverReportsZeroLengthSubframes() {
    return driverReportsZeroLengthSubframes;
  }

  /** @return true if this is a 0-length subframe; false otherwise. */
  public boolean isZeroLengthSubframe() {
    return zeroLengthSubframe;
  }

  /** @return true if the last subframe is known; false otherwise. */
  public boolean isLastSubframeKnown() {
    return lastSubframeKnown;
  }

  /** @return true if this is the last subframe; false otherwise. */
  public boolean isLastSubframe() {
    return lastSubframe;
  }

  /** @return true if delimiter CRC error on this subframe; false otherwise. */
  public boolean isDelimiterCrcError() {
    return delimiterCrcError;
  }

  /** @return true if the delimiter CRC value is known; false otherwise. */
  public boolean isDelimiterCrcValueKnown() {
    return delimiterCrcValueKnown;
  }

  /** @return true if the 10th MSB of the flags field is set to 1; false otherwise. */
  public boolean getTenthMsbOfFlags() {
    return tenthMsbOfFlags;
  }

  /** @return true if the 9th MSB of the flags field is set to 1; false otherwise. */
  public boolean getNinthMsbOfFlags() {
    return ninthMsbOfFlags;
  }

  /** @return true if the 8th MSB of the flags field is set to 1; false otherwise. */
  public boolean getEighthMsbOfFlags() {
    return eighthMsbOfFlags;
  }

  /** @return true if the 7th MSB of the flags field is set to 1; false otherwise. */
  public boolean getSeventhMsbOfFlags() {
    return seventhMsbOfFlags;
  }

  /** @return true if the 6th MSB of the flags field is set to 1; false otherwise. */
  public boolean getSixthMsbOfFlags() {
    return sixthMsbOfFlags;
  }

  /** @return true if the 5th MSB of the flags field is set to 1; false otherwise. */
  public boolean getFifthMsbOfFlags() {
    return fifthMsbOfFlags;
  }

  /** @return true if the 4th MSB of the flags field is set to 1; false otherwise. */
  public boolean getFourthMsbOfFlags() {
    return fourthMsbOfFlags;
  }

  /** @return true if the 3rd MSB of the flags field is set to 1; false otherwise. */
  public boolean getThirdMsbOfFlags() {
    return thirdMsbOfFlags;
  }

  /** @return true if the 2nd MSB of the flags field is set to 1; false otherwise. */
  public boolean getSecondMsbOfFlags() {
    return secondMsbOfFlags;
  }

  /** @return true if the MSB of the flags field is set to 1; false otherwise. */
  public boolean getMsbOfFlags() {
    return msbOfFlags;
  }

  /** @return delimiterCrcValue */
  public byte getDelimiterCrcValue() {
    return delimiterCrcValue;
  }

  /** @return reserved */
  public byte getReserved() {
    return reserved;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[LENGTH];

    System.arraycopy(
        ByteArrays.toByteArray(referenceNumber, ByteOrder.LITTLE_ENDIAN), 0, data, 0, 4);
    if (driverReportsZeroLengthSubframes) {
      data[4] |= 0x01;
    }
    if (zeroLengthSubframe) {
      data[4] |= 0x02;
    }
    if (lastSubframeKnown) {
      data[4] |= 0x04;
    }
    if (lastSubframe) {
      data[4] |= 0x08;
    }
    if (delimiterCrcError) {
      data[4] |= 0x10;
    }
    if (delimiterCrcValueKnown) {
      data[4] |= 0x20;
    }
    if (tenthMsbOfFlags) {
      data[4] |= 0x40;
    }
    if (ninthMsbOfFlags) {
      data[4] |= 0x80;
    }
    if (eighthMsbOfFlags) {
      data[5] |= 0x01;
    }
    if (seventhMsbOfFlags) {
      data[5] |= 0x02;
    }
    if (sixthMsbOfFlags) {
      data[5] |= 0x04;
    }
    if (fifthMsbOfFlags) {
      data[5] |= 0x08;
    }
    if (fourthMsbOfFlags) {
      data[5] |= 0x10;
    }
    if (thirdMsbOfFlags) {
      data[5] |= 0x20;
    }
    if (secondMsbOfFlags) {
      data[5] |= 0x40;
    }
    if (msbOfFlags) {
      data[5] |= 0x80;
    }
    data[6] = delimiterCrcValue;
    data[7] = reserved;

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
        .append("A-MPDU status: ")
        .append(ls)
        .append(indent)
        .append("  reference number: ")
        .append(getReferenceNumberAsLong())
        .append(ls)
        .append(indent)
        .append("  driver reports 0-length subframes: ")
        .append(driverReportsZeroLengthSubframes)
        .append(ls)
        .append(indent)
        .append("  0-length subframe: ")
        .append(zeroLengthSubframe)
        .append(ls)
        .append(indent)
        .append("  last subframe is known: ")
        .append(lastSubframeKnown)
        .append(ls)
        .append(indent)
        .append("  last subframe: ")
        .append(lastSubframe)
        .append(ls)
        .append(indent)
        .append("  delimiter CRC error: ")
        .append(delimiterCrcError)
        .append(ls)
        .append(indent)
        .append("  delimiter CRC value is known: ")
        .append(delimiterCrcValueKnown)
        .append(ls)
        .append(indent)
        .append("  10th MSB of flags: ")
        .append(tenthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  9th MSB of flags: ")
        .append(ninthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  8th MSB of flags: ")
        .append(eighthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  7th MSB of flags: ")
        .append(seventhMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  6th MSB of flags: ")
        .append(sixthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  5th MSB of flags: ")
        .append(fifthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  4th MSB of flags: ")
        .append(fourthMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  3rd MSB of flags: ")
        .append(thirdMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  2nd MSB of flags: ")
        .append(secondMsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  MSB of flags: ")
        .append(msbOfFlags)
        .append(ls)
        .append(indent)
        .append("  delimiter CRC value: 0x")
        .append(ByteArrays.toHexString(delimiterCrcValue, ""))
        .append(ls)
        .append(indent)
        .append("  reserved: 0x")
        .append(ByteArrays.toHexString(reserved, ""))
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (delimiterCrcError ? 1231 : 1237);
    result = prime * result + delimiterCrcValue;
    result = prime * result + (delimiterCrcValueKnown ? 1231 : 1237);
    result = prime * result + (driverReportsZeroLengthSubframes ? 1231 : 1237);
    result = prime * result + (eighthMsbOfFlags ? 1231 : 1237);
    result = prime * result + (fifthMsbOfFlags ? 1231 : 1237);
    result = prime * result + (fourthMsbOfFlags ? 1231 : 1237);
    result = prime * result + (lastSubframe ? 1231 : 1237);
    result = prime * result + (lastSubframeKnown ? 1231 : 1237);
    result = prime * result + (msbOfFlags ? 1231 : 1237);
    result = prime * result + (ninthMsbOfFlags ? 1231 : 1237);
    result = prime * result + referenceNumber;
    result = prime * result + reserved;
    result = prime * result + (secondMsbOfFlags ? 1231 : 1237);
    result = prime * result + (seventhMsbOfFlags ? 1231 : 1237);
    result = prime * result + (sixthMsbOfFlags ? 1231 : 1237);
    result = prime * result + (tenthMsbOfFlags ? 1231 : 1237);
    result = prime * result + (thirdMsbOfFlags ? 1231 : 1237);
    result = prime * result + (zeroLengthSubframe ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataAMpduStatus other = (RadiotapDataAMpduStatus) obj;
    if (delimiterCrcError != other.delimiterCrcError) return false;
    if (delimiterCrcValue != other.delimiterCrcValue) return false;
    if (delimiterCrcValueKnown != other.delimiterCrcValueKnown) return false;
    if (driverReportsZeroLengthSubframes != other.driverReportsZeroLengthSubframes) return false;
    if (eighthMsbOfFlags != other.eighthMsbOfFlags) return false;
    if (fifthMsbOfFlags != other.fifthMsbOfFlags) return false;
    if (fourthMsbOfFlags != other.fourthMsbOfFlags) return false;
    if (lastSubframe != other.lastSubframe) return false;
    if (lastSubframeKnown != other.lastSubframeKnown) return false;
    if (msbOfFlags != other.msbOfFlags) return false;
    if (ninthMsbOfFlags != other.ninthMsbOfFlags) return false;
    if (referenceNumber != other.referenceNumber) return false;
    if (reserved != other.reserved) return false;
    if (secondMsbOfFlags != other.secondMsbOfFlags) return false;
    if (seventhMsbOfFlags != other.seventhMsbOfFlags) return false;
    if (sixthMsbOfFlags != other.sixthMsbOfFlags) return false;
    if (tenthMsbOfFlags != other.tenthMsbOfFlags) return false;
    if (thirdMsbOfFlags != other.thirdMsbOfFlags) return false;
    if (zeroLengthSubframe != other.zeroLengthSubframe) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private int referenceNumber;
    private boolean driverReportsZeroLengthSubframes;
    private boolean zeroLengthSubframe;
    private boolean lastSubframeKnown;
    private boolean lastSubframe;
    private boolean delimiterCrcError;
    private boolean delimiterCrcValueKnown;
    private boolean tenthMsbOfFlags;
    private boolean ninthMsbOfFlags;
    private boolean eighthMsbOfFlags;
    private boolean seventhMsbOfFlags;
    private boolean sixthMsbOfFlags;
    private boolean fifthMsbOfFlags;
    private boolean fourthMsbOfFlags;
    private boolean thirdMsbOfFlags;
    private boolean secondMsbOfFlags;
    private boolean msbOfFlags;
    private byte delimiterCrcValue;
    private byte reserved;

    /** */
    public Builder() {}

    private Builder(RadiotapDataAMpduStatus obj) {
      this.referenceNumber = obj.referenceNumber;
      this.driverReportsZeroLengthSubframes = obj.driverReportsZeroLengthSubframes;
      this.zeroLengthSubframe = obj.zeroLengthSubframe;
      this.lastSubframeKnown = obj.lastSubframeKnown;
      this.lastSubframe = obj.lastSubframe;
      this.delimiterCrcError = obj.delimiterCrcError;
      this.delimiterCrcValueKnown = obj.delimiterCrcValueKnown;
      this.tenthMsbOfFlags = obj.tenthMsbOfFlags;
      this.ninthMsbOfFlags = obj.ninthMsbOfFlags;
      this.eighthMsbOfFlags = obj.eighthMsbOfFlags;
      this.seventhMsbOfFlags = obj.seventhMsbOfFlags;
      this.sixthMsbOfFlags = obj.sixthMsbOfFlags;
      this.fifthMsbOfFlags = obj.fifthMsbOfFlags;
      this.fourthMsbOfFlags = obj.fourthMsbOfFlags;
      this.thirdMsbOfFlags = obj.thirdMsbOfFlags;
      this.secondMsbOfFlags = obj.secondMsbOfFlags;
      this.msbOfFlags = obj.msbOfFlags;
      this.delimiterCrcValue = obj.delimiterCrcValue;
      this.reserved = obj.reserved;
    }

    /**
     * @param referenceNumber referenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder referenceNumber(int referenceNumber) {
      this.referenceNumber = referenceNumber;
      return this;
    }

    /**
     * @param driverReportsZeroLengthSubframes driverReportsZeroLengthSubframes
     * @return this Builder object for method chaining.
     */
    public Builder driverReportsZeroLengthSubframes(boolean driverReportsZeroLengthSubframes) {
      this.driverReportsZeroLengthSubframes = driverReportsZeroLengthSubframes;
      return this;
    }

    /**
     * @param zeroLengthSubframe zeroLengthSubframe
     * @return this Builder object for method chaining.
     */
    public Builder zeroLengthSubframe(boolean zeroLengthSubframe) {
      this.zeroLengthSubframe = zeroLengthSubframe;
      return this;
    }

    /**
     * @param lastSubframeKnown lastSubframeKnown
     * @return this Builder object for method chaining.
     */
    public Builder lastSubframeKnown(boolean lastSubframeKnown) {
      this.lastSubframeKnown = lastSubframeKnown;
      return this;
    }

    /**
     * @param lastSubframe lastSubframe
     * @return this Builder object for method chaining.
     */
    public Builder lastSubframe(boolean lastSubframe) {
      this.lastSubframe = lastSubframe;
      return this;
    }

    /**
     * @param delimiterCrcError delimiterCrcError
     * @return this Builder object for method chaining.
     */
    public Builder delimiterCrcError(boolean delimiterCrcError) {
      this.delimiterCrcError = delimiterCrcError;
      return this;
    }

    /**
     * @param delimiterCrcValueKnown delimiterCrcValueKnown
     * @return this Builder object for method chaining.
     */
    public Builder delimiterCrcValueKnown(boolean delimiterCrcValueKnown) {
      this.delimiterCrcValueKnown = delimiterCrcValueKnown;
      return this;
    }

    /**
     * @param tenthMsbOfFlags tenthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder tenthMsbOfFlags(boolean tenthMsbOfFlags) {
      this.tenthMsbOfFlags = tenthMsbOfFlags;
      return this;
    }

    /**
     * @param ninthMsbOfFlags ninthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder ninthMsbOfFlags(boolean ninthMsbOfFlags) {
      this.ninthMsbOfFlags = ninthMsbOfFlags;
      return this;
    }

    /**
     * @param eighthMsbOfFlags eighthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder eighthMsbOfFlags(boolean eighthMsbOfFlags) {
      this.eighthMsbOfFlags = eighthMsbOfFlags;
      return this;
    }

    /**
     * @param seventhMsbOfFlags seventhMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder seventhMsbOfFlags(boolean seventhMsbOfFlags) {
      this.seventhMsbOfFlags = seventhMsbOfFlags;
      return this;
    }

    /**
     * @param sixthMsbOfFlags sixthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder sixthMsbOfFlags(boolean sixthMsbOfFlags) {
      this.sixthMsbOfFlags = sixthMsbOfFlags;
      return this;
    }

    /**
     * @param fifthMsbOfFlags fifthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder fifthMsbOfFlags(boolean fifthMsbOfFlags) {
      this.fifthMsbOfFlags = fifthMsbOfFlags;
      return this;
    }

    /**
     * @param fourthMsbOfFlags fourthMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder fourthMsbOfFlags(boolean fourthMsbOfFlags) {
      this.fourthMsbOfFlags = fourthMsbOfFlags;
      return this;
    }

    /**
     * @param thirdMsbOfFlags thirdMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder thirdMsbOfFlags(boolean thirdMsbOfFlags) {
      this.thirdMsbOfFlags = thirdMsbOfFlags;
      return this;
    }

    /**
     * @param secondMsbOfFlags secondMsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder secondMsbOfFlags(boolean secondMsbOfFlags) {
      this.secondMsbOfFlags = secondMsbOfFlags;
      return this;
    }

    /**
     * @param msbOfFlags msbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder msbOfFlags(boolean msbOfFlags) {
      this.msbOfFlags = msbOfFlags;
      return this;
    }

    /**
     * @param delimiterCrcValue delimiterCrcValue
     * @return this Builder object for method chaining.
     */
    public Builder delimiterCrcValue(byte delimiterCrcValue) {
      this.delimiterCrcValue = delimiterCrcValue;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /** @return a new RadiotapAMpduStatus object. */
    public RadiotapDataAMpduStatus build() {
      return new RadiotapDataAMpduStatus(this);
    }
  }
}
