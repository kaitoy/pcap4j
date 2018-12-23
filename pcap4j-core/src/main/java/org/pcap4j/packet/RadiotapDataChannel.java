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
 * Radiotap Channel field. Tx/Rx frequency in MHz and flags.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Rate">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataChannel implements RadiotapData {

  /** */
  private static final long serialVersionUID = 3645927613193110605L;

  private static final int LENGTH = 4;

  private final short frequency;
  private final boolean lsbOfFlags;
  private final boolean secondLsbOfFlags;
  private final boolean thirdLsbOfFlags;
  private final boolean fourthLsbOfFlags;
  private final boolean turbo;
  private final boolean cck;
  private final boolean ofdm;
  private final boolean twoGhzSpectrum;
  private final boolean fiveGhzSpectrum;
  private final boolean onlyPassiveScan;
  private final boolean dynamicCckOfdm;
  private final boolean gfsk;
  private final boolean gsm;
  private final boolean staticTurbo;
  private final boolean halfRate;
  private final boolean quarterRate;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapChannel object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataChannel newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataChannel(rawData, offset, length);
  }

  private RadiotapDataChannel(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapChannel (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.frequency = ByteArrays.getShort(rawData, offset, ByteOrder.LITTLE_ENDIAN);
    this.lsbOfFlags = (rawData[offset + 2] & 0x01) != 0;
    this.secondLsbOfFlags = (rawData[offset + 2] & 0x02) != 0;
    this.thirdLsbOfFlags = (rawData[offset + 2] & 0x04) != 0;
    this.fourthLsbOfFlags = (rawData[offset + 2] & 0x08) != 0;
    this.turbo = (rawData[offset + 2] & 0x10) != 0;
    this.cck = (rawData[offset + 2] & 0x20) != 0;
    this.ofdm = (rawData[offset + 2] & 0x40) != 0;
    this.twoGhzSpectrum = (rawData[offset + 2] & 0x80) != 0;
    this.fiveGhzSpectrum = (rawData[offset + 3] & 0x01) != 0;
    this.onlyPassiveScan = (rawData[offset + 3] & 0x02) != 0;
    this.dynamicCckOfdm = (rawData[offset + 3] & 0x04) != 0;
    this.gfsk = (rawData[offset + 3] & 0x08) != 0;
    this.gsm = (rawData[offset + 3] & 0x10) != 0;
    this.staticTurbo = (rawData[offset + 3] & 0x20) != 0;
    this.halfRate = (rawData[offset + 3] & 0x40) != 0;
    this.quarterRate = (rawData[offset + 3] & 0x80) != 0;
  }

  private RadiotapDataChannel(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.frequency = builder.frequency;
    this.lsbOfFlags = builder.lsbOfFlags;
    this.secondLsbOfFlags = builder.secondLsbOfFlags;
    this.thirdLsbOfFlags = builder.thirdLsbOfFlags;
    this.fourthLsbOfFlags = builder.fourthLsbOfFlags;
    this.turbo = builder.turbo;
    this.cck = builder.cck;
    this.ofdm = builder.ofdm;
    this.twoGhzSpectrum = builder.twoGhzSpectrum;
    this.fiveGhzSpectrum = builder.fiveGhzSpectrum;
    this.onlyPassiveScan = builder.onlyPassiveScan;
    this.dynamicCckOfdm = builder.dynamicCckOfdm;
    this.gfsk = builder.gfsk;
    this.gsm = builder.gsm;
    this.staticTurbo = builder.staticTurbo;
    this.halfRate = builder.halfRate;
    this.quarterRate = builder.quarterRate;
  }

  /**
   * Tx/Rx frequency in MHz
   *
   * @return frequency (unit: MHz)
   */
  public short getFrequency() {
    return frequency;
  }

  /**
   * Tx/Rx frequency in MHz
   *
   * @return frequency (unit: MHz)
   */
  public int getFrequencyAsInt() {
    return frequency & 0xFFFF;
  }

  /** @return true if the LSB of the flags field is set to 1; otherwise false. */
  public boolean getLsbOfFlags() {
    return lsbOfFlags;
  }

  /** @return true if the second LSB of the flags field is set to 1; otherwise false. */
  public boolean getSecondLsbOfFlags() {
    return secondLsbOfFlags;
  }

  /** @return true if the third LSB of the flags field is set to 1; otherwise false. */
  public boolean getThirdLsbOfFlags() {
    return thirdLsbOfFlags;
  }

  /** @return true if the fourth LSB of the flags field is set to 1; otherwise false. */
  public boolean getFourthLsbOfFlags() {
    return fourthLsbOfFlags;
  }

  /** @return turbo */
  public boolean isTurbo() {
    return turbo;
  }

  /** @return cck */
  public boolean isCck() {
    return cck;
  }

  /** @return ofdm */
  public boolean isOfdm() {
    return ofdm;
  }

  /** @return twoGhzSpectrum */
  public boolean isTwoGhzSpectrum() {
    return twoGhzSpectrum;
  }

  /** @return fiveGhzSpectrum */
  public boolean isFiveGhzSpectrum() {
    return fiveGhzSpectrum;
  }

  /** @return onlyPassiveScan */
  public boolean isOnlyPassiveScan() {
    return onlyPassiveScan;
  }

  /** @return dynamicCckOfdm */
  public boolean isDynamicCckOfdm() {
    return dynamicCckOfdm;
  }

  /** @return gfsk */
  public boolean isGfsk() {
    return gfsk;
  }

  /** @return gsm */
  public boolean isGsm() {
    return gsm;
  }

  /** @return staticTurbo */
  public boolean isStaticTurbo() {
    return staticTurbo;
  }

  /** @return halfRate */
  public boolean isHalfRate() {
    return halfRate;
  }

  /** @return quarterRate */
  public boolean isQuarterRate() {
    return quarterRate;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[4];
    System.arraycopy(
        ByteArrays.toByteArray(frequency, ByteOrder.LITTLE_ENDIAN),
        0,
        data,
        0,
        ByteArrays.SHORT_SIZE_IN_BYTES);
    if (lsbOfFlags) {
      data[2] |= 0x01;
    }
    if (secondLsbOfFlags) {
      data[2] |= 0x02;
    }
    if (thirdLsbOfFlags) {
      data[2] |= 0x04;
    }
    if (fourthLsbOfFlags) {
      data[2] |= 0x08;
    }
    if (turbo) {
      data[2] |= 0x10;
    }
    if (cck) {
      data[2] |= 0x20;
    }
    if (ofdm) {
      data[2] |= 0x40;
    }
    if (twoGhzSpectrum) {
      data[2] |= 0x80;
    }
    if (fiveGhzSpectrum) {
      data[3] |= 0x01;
    }
    if (onlyPassiveScan) {
      data[3] |= 0x02;
    }
    if (dynamicCckOfdm) {
      data[3] |= 0x04;
    }
    if (gfsk) {
      data[3] |= 0x08;
    }
    if (gsm) {
      data[3] |= 0x10;
    }
    if (staticTurbo) {
      data[3] |= 0x20;
    }
    if (halfRate) {
      data[3] |= 0x40;
    }
    if (quarterRate) {
      data[3] |= 0x80;
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
        .append("Channel: ")
        .append(ls)
        .append(indent)
        .append("  Frequency: ")
        .append(getFrequencyAsInt())
        .append(" MHz")
        .append(ls)
        .append(indent)
        .append("  LSB of flags: ")
        .append(lsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  2nd LSB of flags: ")
        .append(secondLsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  3rd LSB of flags: ")
        .append(thirdLsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  4th LSB of flags: ")
        .append(fourthLsbOfFlags)
        .append(ls)
        .append(indent)
        .append("  Turbo: ")
        .append(turbo)
        .append(ls)
        .append(indent)
        .append("  CCK: ")
        .append(cck)
        .append(ls)
        .append(indent)
        .append("  OFDM: ")
        .append(ofdm)
        .append(ls)
        .append(indent)
        .append("  2 GHz spectrum: ")
        .append(twoGhzSpectrum)
        .append(ls)
        .append(indent)
        .append("  5 GHz spectrum: ")
        .append(fiveGhzSpectrum)
        .append(ls)
        .append(indent)
        .append("  Only passive scan: ")
        .append(onlyPassiveScan)
        .append(ls)
        .append(indent)
        .append("  Dynamic CCK-OFDM: ")
        .append(dynamicCckOfdm)
        .append(ls)
        .append(indent)
        .append("  GFSK: ")
        .append(gfsk)
        .append(ls)
        .append(indent)
        .append("  GSM: ")
        .append(gsm)
        .append(ls)
        .append(indent)
        .append("  Static Turbo: ")
        .append(staticTurbo)
        .append(ls)
        .append(indent)
        .append("  Half rate: ")
        .append(halfRate)
        .append(ls)
        .append(indent)
        .append("  Quarter rate: ")
        .append(quarterRate)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (cck ? 1231 : 1237);
    result = prime * result + (dynamicCckOfdm ? 1231 : 1237);
    result = prime * result + (fiveGhzSpectrum ? 1231 : 1237);
    result = prime * result + (fourthLsbOfFlags ? 1231 : 1237);
    result = prime * result + frequency;
    result = prime * result + (gfsk ? 1231 : 1237);
    result = prime * result + (gsm ? 1231 : 1237);
    result = prime * result + (halfRate ? 1231 : 1237);
    result = prime * result + (lsbOfFlags ? 1231 : 1237);
    result = prime * result + (ofdm ? 1231 : 1237);
    result = prime * result + (onlyPassiveScan ? 1231 : 1237);
    result = prime * result + (quarterRate ? 1231 : 1237);
    result = prime * result + (secondLsbOfFlags ? 1231 : 1237);
    result = prime * result + (staticTurbo ? 1231 : 1237);
    result = prime * result + (thirdLsbOfFlags ? 1231 : 1237);
    result = prime * result + (turbo ? 1231 : 1237);
    result = prime * result + (twoGhzSpectrum ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataChannel other = (RadiotapDataChannel) obj;
    if (cck != other.cck) return false;
    if (dynamicCckOfdm != other.dynamicCckOfdm) return false;
    if (fiveGhzSpectrum != other.fiveGhzSpectrum) return false;
    if (fourthLsbOfFlags != other.fourthLsbOfFlags) return false;
    if (frequency != other.frequency) return false;
    if (gfsk != other.gfsk) return false;
    if (gsm != other.gsm) return false;
    if (halfRate != other.halfRate) return false;
    if (lsbOfFlags != other.lsbOfFlags) return false;
    if (ofdm != other.ofdm) return false;
    if (onlyPassiveScan != other.onlyPassiveScan) return false;
    if (quarterRate != other.quarterRate) return false;
    if (secondLsbOfFlags != other.secondLsbOfFlags) return false;
    if (staticTurbo != other.staticTurbo) return false;
    if (thirdLsbOfFlags != other.thirdLsbOfFlags) return false;
    if (turbo != other.turbo) return false;
    if (twoGhzSpectrum != other.twoGhzSpectrum) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private short frequency;
    private boolean lsbOfFlags;
    private boolean secondLsbOfFlags;
    private boolean thirdLsbOfFlags;
    private boolean fourthLsbOfFlags;
    private boolean turbo;
    private boolean cck;
    private boolean ofdm;
    private boolean twoGhzSpectrum;
    private boolean fiveGhzSpectrum;
    private boolean onlyPassiveScan;
    private boolean dynamicCckOfdm;
    private boolean gfsk;
    private boolean gsm;
    private boolean staticTurbo;
    private boolean halfRate;
    private boolean quarterRate;

    /** */
    public Builder() {}

    private Builder(RadiotapDataChannel obj) {
      this.frequency = obj.frequency;
      this.lsbOfFlags = obj.lsbOfFlags;
      this.secondLsbOfFlags = obj.secondLsbOfFlags;
      this.thirdLsbOfFlags = obj.thirdLsbOfFlags;
      this.fourthLsbOfFlags = obj.fourthLsbOfFlags;
      this.turbo = obj.turbo;
      this.cck = obj.cck;
      this.ofdm = obj.ofdm;
      this.twoGhzSpectrum = obj.twoGhzSpectrum;
      this.fiveGhzSpectrum = obj.fiveGhzSpectrum;
      this.onlyPassiveScan = obj.onlyPassiveScan;
      this.dynamicCckOfdm = obj.dynamicCckOfdm;
      this.gfsk = obj.gfsk;
      this.gsm = obj.gsm;
      this.staticTurbo = obj.staticTurbo;
      this.halfRate = obj.halfRate;
      this.quarterRate = obj.quarterRate;
    }

    /**
     * @param frequency frequency
     * @return this Builder object for method chaining.
     */
    public Builder frequency(short frequency) {
      this.frequency = frequency;
      return this;
    }

    /**
     * @param lsbOfFlags lsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder lsbOfFlags(boolean lsbOfFlags) {
      this.lsbOfFlags = lsbOfFlags;
      return this;
    }

    /**
     * @param secondLsbOfFlags secondLsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder secondLsbOfFlags(boolean secondLsbOfFlags) {
      this.secondLsbOfFlags = secondLsbOfFlags;
      return this;
    }

    /**
     * @param thirdLsbOfFlags thirdLsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder thirdLsbOfFlags(boolean thirdLsbOfFlags) {
      this.thirdLsbOfFlags = thirdLsbOfFlags;
      return this;
    }

    /**
     * @param fourthLsbOfFlags fourthLsbOfFlags
     * @return this Builder object for method chaining.
     */
    public Builder fourthLsbOfFlags(boolean fourthLsbOfFlags) {
      this.fourthLsbOfFlags = fourthLsbOfFlags;
      return this;
    }

    /**
     * @param turbo turbo
     * @return this Builder object for method chaining.
     */
    public Builder turbo(boolean turbo) {
      this.turbo = turbo;
      return this;
    }

    /**
     * @param cck cck
     * @return this Builder object for method chaining.
     */
    public Builder cck(boolean cck) {
      this.cck = cck;
      return this;
    }

    /**
     * @param ofdm ofdm
     * @return this Builder object for method chaining.
     */
    public Builder ofdm(boolean ofdm) {
      this.ofdm = ofdm;
      return this;
    }

    /**
     * @param twoGhzSpectrum twoGhzSpectrum
     * @return this Builder object for method chaining.
     */
    public Builder twoGhzSpectrum(boolean twoGhzSpectrum) {
      this.twoGhzSpectrum = twoGhzSpectrum;
      return this;
    }

    /**
     * @param fiveGhzSpectrum fiveGhzSpectrum
     * @return this Builder object for method chaining.
     */
    public Builder fiveGhzSpectrum(boolean fiveGhzSpectrum) {
      this.fiveGhzSpectrum = fiveGhzSpectrum;
      return this;
    }

    /**
     * @param onlyPassiveScan onlyPassiveScan
     * @return this Builder object for method chaining.
     */
    public Builder onlyPassiveScan(boolean onlyPassiveScan) {
      this.onlyPassiveScan = onlyPassiveScan;
      return this;
    }

    /**
     * @param dynamicCckOfdm dynamicCckOfdm
     * @return this Builder object for method chaining.
     */
    public Builder dynamicCckOfdm(boolean dynamicCckOfdm) {
      this.dynamicCckOfdm = dynamicCckOfdm;
      return this;
    }

    /**
     * @param gfsk gfsk
     * @return this Builder object for method chaining.
     */
    public Builder gfsk(boolean gfsk) {
      this.gfsk = gfsk;
      return this;
    }

    /**
     * @param gsm gsm
     * @return this Builder object for method chaining.
     */
    public Builder gsm(boolean gsm) {
      this.gsm = gsm;
      return this;
    }

    /**
     * @param staticTurbo staticTurbo
     * @return this Builder object for method chaining.
     */
    public Builder staticTurbo(boolean staticTurbo) {
      this.staticTurbo = staticTurbo;
      return this;
    }

    /**
     * @param halfRate halfRate
     * @return this Builder object for method chaining.
     */
    public Builder halfRate(boolean halfRate) {
      this.halfRate = halfRate;
      return this;
    }

    /**
     * @param quarterRate quarterRate
     * @return this Builder object for method chaining.
     */
    public Builder quarterRate(boolean quarterRate) {
      this.quarterRate = quarterRate;
      return this;
    }

    /** @return a new RadiotapChannel object. */
    public RadiotapDataChannel build() {
      return new RadiotapDataChannel(this);
    }
  }
}
