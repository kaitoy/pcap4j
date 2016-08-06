/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.nio.ByteOrder;

import org.pcap4j.packet.RadiotapPacket.RadiotapDataField;
import org.pcap4j.util.ByteArrays;

/**
 * Radiotap Channel field.
 * Tx/Rx frequency in MHz and flags.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/Rate">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapChannel implements RadiotapDataField {

  /**
   *
   */
  private static final long serialVersionUID = -3015189452751015438L;

  private static final int LENGTH = 4;

  private final short frequency;
  private final boolean lsb;
  private final boolean secondLsb;
  private final boolean thirdLsb;
  private final boolean fourthLsb;
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
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapChannel object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapChannel newInstance(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapChannel(rawData, offset, length);
  }

  private RadiotapChannel(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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
    this.lsb = (rawData[offset + 2] & 0x01) != 0;
    this.secondLsb = (rawData[offset + 2] & 0x02) != 0;
    this.thirdLsb = (rawData[offset + 2] & 0x04) != 0;
    this.fourthLsb = (rawData[offset + 2] & 0x08) != 0;
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

  private RadiotapChannel(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }

    this.frequency = builder.frequency;
    this.lsb = builder.lsb;
    this.secondLsb = builder.secondLsb;
    this.thirdLsb = builder.thirdLsb;
    this.fourthLsb = builder.fourthLsb;
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
  public short getFrequency() { return frequency; }

  /**
   * Tx/Rx frequency in MHz
   *
   * @return frequency (unit: MHz)
   */
  public int getFrequencyAsInt() { return frequency & 0xFFFF; }

  /**
   * @return lsbtrue if the LSB is set to 1; otherwise false.
   */
  public boolean getLsb() {
    return lsb;
  }

  /**
   * @return true if the second LSB is set to 1; otherwise false.
   */
  public boolean getSecondLsb() {
    return secondLsb;
  }

  /**
   * @return true if the third LSB is set to 1; otherwise false.
   */
  public boolean getThirdLsb() {
    return thirdLsb;
  }

  /**
   * @return true if the fourth LSB is set to 1; otherwise false.
   */
  public boolean getFourthLsb() {
    return fourthLsb;
  }

  /**
   * @return turbo
   */
  public boolean isTurbo() {
    return turbo;
  }

  /**
   * @return cck
   */
  public boolean isCck() {
    return cck;
  }

  /**
   * @return ofdm
   */
  public boolean isOfdm() {
    return ofdm;
  }

  /**
   * @return twoGhzSpectrum
   */
  public boolean isTwoGhzSpectrum() {
    return twoGhzSpectrum;
  }

  /**
   * @return fiveGhzSpectrum
   */
  public boolean isFiveGhzSpectrum() {
    return fiveGhzSpectrum;
  }

  /**
   * @return onlyPassiveScan
   */
  public boolean isOnlyPassiveScan() {
    return onlyPassiveScan;
  }

  /**
   * @return dynamicCckOfdm
   */
  public boolean isDynamicCckOfdm() {
    return dynamicCckOfdm;
  }

  /**
   * @return gfsk
   */
  public boolean isGfsk() {
    return gfsk;
  }

  /**
   * @return gsm
   */
  public boolean isGsm() {
    return gsm;
  }

  /**
   * @return staticTurbo
   */
  public boolean isStaticTurbo() {
    return staticTurbo;
  }

  /**
   * @return halfRate
   */
  public boolean isHalfRate() {
    return halfRate;
  }

  /**
   * @return quarterRate
   */
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
      ByteArrays.toByteArray(frequency, ByteOrder.LITTLE_ENDIAN), 0,
      data, 0, ByteArrays.SHORT_SIZE_IN_BYTES
    );
    if (lsb) { data[2] |= 0x01; }
    if (secondLsb) { data[2] |= 0x02; }
    if (thirdLsb) { data[2] |= 0x04; }
    if (fourthLsb) { data[2] |= 0x08; }
    if (turbo) { data[2] |= 0x10; }
    if (cck) { data[2] |= 0x20; }
    if (ofdm) { data[2] |= 0x40; }
    if (twoGhzSpectrum) { data[2] |= 0x80; }
    if (fiveGhzSpectrum) { data[3] |= 0x01; }
    if (onlyPassiveScan) { data[3] |= 0x02; }
    if (dynamicCckOfdm) { data[3] |= 0x04; }
    if (gfsk) { data[3] |= 0x08; }
    if (gsm) { data[3] |= 0x10; }
    if (staticTurbo) { data[3] |= 0x20; }
    if (halfRate) { data[3] |= 0x40; }
    if (quarterRate) { data[3] |= 0x80; }
    return data;
  }

  /**
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Channel: [Frequency: ")
      .append(getFrequencyAsInt())
      .append(" MHz], [LSB: ")
      .append(lsb)
      .append("], [2nd LSB: ")
      .append(secondLsb)
      .append("], [3rd LSB: ")
      .append(thirdLsb)
      .append("], [4th LSB: ")
      .append(fourthLsb)
      .append("], [Turbo: ")
      .append(turbo)
      .append("], [CCK: ")
      .append(cck)
      .append("], [OFDM: ")
      .append(ofdm)
      .append("], [2 GHz spectrum: ")
      .append(twoGhzSpectrum)
      .append("], [5 GHz spectrum: ")
      .append(fiveGhzSpectrum)
      .append("], [Only passive scan: ")
      .append(onlyPassiveScan)
      .append("], [Dynamic CCK-OFDM: ")
      .append(dynamicCckOfdm)
      .append("], [GFSK: ")
      .append(gfsk)
      .append("], [GSM: ")
      .append(gsm)
      .append("], [Static Turbo: ")
      .append(staticTurbo)
      .append("], [Half rate: ")
      .append(halfRate)
      .append("], [Quarter rate: ")
      .append(quarterRate)
      .append("]]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (cck ? 1231 : 1237);
    result = prime * result + (dynamicCckOfdm ? 1231 : 1237);
    result = prime * result + (fiveGhzSpectrum ? 1231 : 1237);
    result = prime * result + (fourthLsb ? 1231 : 1237);
    result = prime * result + frequency;
    result = prime * result + (gfsk ? 1231 : 1237);
    result = prime * result + (gsm ? 1231 : 1237);
    result = prime * result + (halfRate ? 1231 : 1237);
    result = prime * result + (lsb ? 1231 : 1237);
    result = prime * result + (ofdm ? 1231 : 1237);
    result = prime * result + (onlyPassiveScan ? 1231 : 1237);
    result = prime * result + (quarterRate ? 1231 : 1237);
    result = prime * result + (secondLsb ? 1231 : 1237);
    result = prime * result + (staticTurbo ? 1231 : 1237);
    result = prime * result + (thirdLsb ? 1231 : 1237);
    result = prime * result + (turbo ? 1231 : 1237);
    result = prime * result + (twoGhzSpectrum ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    RadiotapChannel other = (RadiotapChannel) obj;
    if (cck != other.cck)
      return false;
    if (dynamicCckOfdm != other.dynamicCckOfdm)
      return false;
    if (fiveGhzSpectrum != other.fiveGhzSpectrum)
      return false;
    if (fourthLsb != other.fourthLsb)
      return false;
    if (frequency != other.frequency)
      return false;
    if (gfsk != other.gfsk)
      return false;
    if (gsm != other.gsm)
      return false;
    if (halfRate != other.halfRate)
      return false;
    if (lsb != other.lsb)
      return false;
    if (ofdm != other.ofdm)
      return false;
    if (onlyPassiveScan != other.onlyPassiveScan)
      return false;
    if (quarterRate != other.quarterRate)
      return false;
    if (secondLsb != other.secondLsb)
      return false;
    if (staticTurbo != other.staticTurbo)
      return false;
    if (thirdLsb != other.thirdLsb)
      return false;
    if (turbo != other.turbo)
      return false;
    if (twoGhzSpectrum != other.twoGhzSpectrum)
      return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private short frequency;
    private boolean lsb;
    private boolean secondLsb;
    private boolean thirdLsb;
    private boolean fourthLsb;
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

    /**
     *
     */
    public Builder() {}

    private Builder(RadiotapChannel obj) {
      this.frequency = obj.frequency;
      this.lsb = obj.lsb;
      this.secondLsb = obj.secondLsb;
      this.thirdLsb = obj.thirdLsb;
      this.fourthLsb = obj.fourthLsb;
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
     * @param lsb lsb
     * @return this Builder object for method chaining.
     */
    public Builder lsb(boolean lsb) {
      this.lsb = lsb;
      return this;
    }

    /**
     * @param secondLsb secondLsb
     * @return this Builder object for method chaining.
     */
    public Builder secondLsb(boolean secondLsb) {
      this.secondLsb = secondLsb;
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

    /**
     * @return a new RadiotapChannel object.
     */
    public RadiotapChannel build() {
      return new RadiotapChannel(this);
    }

  }

}
