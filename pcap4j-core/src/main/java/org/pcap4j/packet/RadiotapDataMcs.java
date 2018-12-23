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
 * Radiotap MCS field.
 *
 * @see <a href="http://www.radiotap.org/defined-fields/MCS">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapDataMcs implements RadiotapData {

  /** */
  private static final long serialVersionUID = 8914690461479810322L;

  private static final int LENGTH = 3;

  private final boolean bandwidthKnown;
  private final boolean mcsIndexKnown;
  private final boolean guardIntervalKnown;
  private final boolean htFormatKnown;
  private final boolean fecTypeKnown;
  private final boolean stbcKnown;
  private final boolean nessKnown;
  private final boolean nessMsb;
  private final Bandwidth bandwidth;
  private final boolean shortGuardInterval;
  private final HtFormat htFormat;
  private final RadiotapFecType fecType;
  private final byte numStbcStreams;
  private final boolean nessLsb;
  private final byte mcsRateIndex;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapMcs object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapDataMcs newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapDataMcs(rawData, offset, length);
  }

  private RadiotapDataMcs(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < LENGTH) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapMcs (")
          .append(LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.bandwidthKnown = (rawData[offset] & 0x01) != 0;
    this.mcsIndexKnown = (rawData[offset] & 0x02) != 0;
    this.guardIntervalKnown = (rawData[offset] & 0x04) != 0;
    this.htFormatKnown = (rawData[offset] & 0x08) != 0;
    this.fecTypeKnown = (rawData[offset] & 0x10) != 0;
    this.stbcKnown = (rawData[offset] & 0x20) != 0;
    this.nessKnown = (rawData[offset] & 0x40) != 0;
    this.nessMsb = (rawData[offset] & 0x80) != 0;
    switch (rawData[offset + 1] & 0x03) {
      case 0:
        this.bandwidth = Bandwidth.BW_20;
        break;
      case 1:
        this.bandwidth = Bandwidth.BW_40;
        break;
      case 2:
        this.bandwidth = Bandwidth.BW_20L;
        break;
      case 3:
        this.bandwidth = Bandwidth.BW_20U;
        break;
      default:
        throw new AssertionError("Never get here.");
    }
    this.shortGuardInterval = (rawData[offset + 1] & 0x04) != 0;
    switch (rawData[offset + 1] & 0x08) {
      case 0:
        this.htFormat = HtFormat.MIXED;
        break;
      default:
        this.htFormat = HtFormat.GREENFIELD;
    }
    switch (rawData[offset + 1] & 0x10) {
      case 0:
        this.fecType = RadiotapFecType.BCC;
        break;
      default:
        this.fecType = RadiotapFecType.LDPC;
    }
    this.numStbcStreams = (byte) ((rawData[offset + 1] & 0x60) >> 5);
    this.nessLsb = (rawData[offset + 1] & 0x80) != 0;
    this.mcsRateIndex = rawData[offset + 2];
  }

  private RadiotapDataMcs(Builder builder) {
    if (builder == null
        || builder.bandwidth == null
        || builder.htFormat == null
        || builder.fecType == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.bandwidth: ")
          .append(builder.bandwidth)
          .append(" builder.htFormat: ")
          .append(builder.htFormat)
          .append(" builder.fecType: ")
          .append(builder.fecType);
      throw new NullPointerException(sb.toString());
    }
    if ((builder.numStbcStreams & 0xFC) != 0) {
      throw new IllegalArgumentException(
          "(builder.numStbcStreams & 0xFC) must be 0. builder.numStbcStreams: "
              + builder.numStbcStreams);
    }

    this.bandwidthKnown = builder.bandwidthKnown;
    this.mcsIndexKnown = builder.mcsIndexKnown;
    this.guardIntervalKnown = builder.guardIntervalKnown;
    this.htFormatKnown = builder.htFormatKnown;
    this.fecTypeKnown = builder.fecTypeKnown;
    this.stbcKnown = builder.stbcKnown;
    this.nessKnown = builder.nessKnown;
    this.nessMsb = builder.nessMsb;
    this.bandwidth = builder.bandwidth;
    this.shortGuardInterval = builder.shortGuardInterval;
    this.htFormat = builder.htFormat;
    this.fecType = builder.fecType;
    this.numStbcStreams = builder.numStbcStreams;
    this.nessLsb = builder.nessLsb;
    this.mcsRateIndex = builder.mcsRateIndex;
  }

  /** @return true if the bandwidth is known; false otherwise. */
  public boolean isBandwidthKnown() {
    return bandwidthKnown;
  }

  /** @return true if the MCS index is known; false otherwise. */
  public boolean isMcsIndexKnown() {
    return mcsIndexKnown;
  }

  /** @return true if the guard interval is known; false otherwise. */
  public boolean isGuardIntervalKnown() {
    return guardIntervalKnown;
  }

  /** @return true if the HT format is known; false otherwise. */
  public boolean isHtFormatKnown() {
    return htFormatKnown;
  }

  /** @return true if the FEC type is known; false otherwise. */
  public boolean isFecTypeKnown() {
    return fecTypeKnown;
  }

  /** @return true if the STBC is known; false otherwise. */
  public boolean isStbcKnown() {
    return stbcKnown;
  }

  /** @return true if the Ness is known; false otherwise. */
  public boolean isNessKnown() {
    return nessKnown;
  }

  /** @return true if the MSB of Ness is 1; false otherwise. */
  public boolean getNessMsb() {
    return nessMsb;
  }

  /** @return bandwidth */
  public Bandwidth getBandwidth() {
    return bandwidth;
  }

  /** @return true if the guard interval is short; false otherwise. */
  public boolean isShortGuardInterval() {
    return shortGuardInterval;
  }

  /** @return htFormat */
  public HtFormat getHtFormat() {
    return htFormat;
  }

  /** @return fecType */
  public RadiotapFecType getFecType() {
    return fecType;
  }

  /** @return numStbcStreams */
  public byte getNumStbcStreams() {
    return numStbcStreams;
  }

  /** @return numStbcStreams */
  public int getNumStbcStreamsAsInt() {
    return numStbcStreams;
  }

  /** @return true if LSB of Ness is 1; false otherwise. */
  public boolean getNessLsb() {
    return nessLsb;
  }

  /** @return mcsRateIndex */
  public byte getMcsRateIndex() {
    return mcsRateIndex;
  }

  /** @return mcsRateIndex */
  public int getMcsRateIndexAsInt() {
    return mcsRateIndex & 0xFF;
  }

  @Override
  public int length() {
    return LENGTH;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[LENGTH];

    if (bandwidthKnown) {
      data[0] |= 0x01;
    }
    if (mcsIndexKnown) {
      data[0] |= 0x02;
    }
    if (guardIntervalKnown) {
      data[0] |= 0x04;
    }
    if (htFormatKnown) {
      data[0] |= 0x08;
    }
    if (fecTypeKnown) {
      data[0] |= 0x10;
    }
    if (stbcKnown) {
      data[0] |= 0x20;
    }
    if (nessKnown) {
      data[0] |= 0x40;
    }
    if (nessMsb) {
      data[0] |= 0x80;
    }

    data[1] = (byte) bandwidth.value;
    if (shortGuardInterval) {
      data[1] |= 0x04;
    }
    if (htFormat == HtFormat.GREENFIELD) {
      data[1] |= 0x08;
    }
    if (fecType == RadiotapFecType.LDPC) {
      data[1] |= 0x10;
    }
    data[1] |= numStbcStreams << 5;
    if (nessLsb) {
      data[1] |= 0x80;
    }

    data[2] = mcsRateIndex;

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
        .append("MCS: ")
        .append(ls)
        .append(indent)
        .append("  bandwidth known: ")
        .append(bandwidthKnown)
        .append(ls)
        .append(indent)
        .append("  MCS index known: ")
        .append(mcsIndexKnown)
        .append(ls)
        .append(indent)
        .append("  guard interval known: ")
        .append(guardIntervalKnown)
        .append(ls)
        .append(indent)
        .append("  HT format known: ")
        .append(htFormatKnown)
        .append(ls)
        .append(indent)
        .append("  FEC type known: ")
        .append(fecTypeKnown)
        .append(ls)
        .append(indent)
        .append("  STBC known: ")
        .append(stbcKnown)
        .append(ls)
        .append(indent)
        .append("  Ness known: ")
        .append(nessKnown)
        .append(ls)
        .append(indent)
        .append("  Ness data known: ")
        .append(nessMsb)
        .append(ls)
        .append(indent)
        .append("  bandwidth: ")
        .append(bandwidth)
        .append(ls)
        .append(indent)
        .append("  short guard interval: ")
        .append(shortGuardInterval)
        .append(ls)
        .append(indent)
        .append("  HT format: ")
        .append(htFormat)
        .append(ls)
        .append(indent)
        .append("  FEC type: ")
        .append(fecType)
        .append(ls)
        .append(indent)
        .append("  Number of STBC streams: ")
        .append(numStbcStreams)
        .append(ls)
        .append(indent)
        .append("  Ness: ")
        .append(nessLsb)
        .append(ls)
        .append(indent)
        .append("  MCS rate index: ")
        .append(getMcsRateIndexAsInt())
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + bandwidth.hashCode();
    result = prime * result + (bandwidthKnown ? 1231 : 1237);
    result = prime * result + fecType.hashCode();
    result = prime * result + (fecTypeKnown ? 1231 : 1237);
    result = prime * result + (guardIntervalKnown ? 1231 : 1237);
    result = prime * result + htFormat.hashCode();
    result = prime * result + (htFormatKnown ? 1231 : 1237);
    result = prime * result + (mcsIndexKnown ? 1231 : 1237);
    result = prime * result + mcsRateIndex;
    result = prime * result + (nessLsb ? 1231 : 1237);
    result = prime * result + (nessMsb ? 1231 : 1237);
    result = prime * result + (nessKnown ? 1231 : 1237);
    result = prime * result + numStbcStreams;
    result = prime * result + (shortGuardInterval ? 1231 : 1237);
    result = prime * result + (stbcKnown ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    RadiotapDataMcs other = (RadiotapDataMcs) obj;
    if (bandwidth != other.bandwidth) return false;
    if (bandwidthKnown != other.bandwidthKnown) return false;
    if (fecType != other.fecType) return false;
    if (fecTypeKnown != other.fecTypeKnown) return false;
    if (guardIntervalKnown != other.guardIntervalKnown) return false;
    if (htFormat != other.htFormat) return false;
    if (htFormatKnown != other.htFormatKnown) return false;
    if (mcsIndexKnown != other.mcsIndexKnown) return false;
    if (mcsRateIndex != other.mcsRateIndex) return false;
    if (nessLsb != other.nessLsb) return false;
    if (nessMsb != other.nessMsb) return false;
    if (nessKnown != other.nessKnown) return false;
    if (numStbcStreams != other.numStbcStreams) return false;
    if (shortGuardInterval != other.shortGuardInterval) return false;
    if (stbcKnown != other.stbcKnown) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private boolean bandwidthKnown;
    private boolean mcsIndexKnown;
    private boolean guardIntervalKnown;
    private boolean htFormatKnown;
    private boolean fecTypeKnown;
    private boolean stbcKnown;
    private boolean nessKnown;
    private boolean nessMsb;
    private Bandwidth bandwidth;
    private boolean shortGuardInterval;
    private HtFormat htFormat;
    private RadiotapFecType fecType;
    private byte numStbcStreams;
    private boolean nessLsb;
    private byte mcsRateIndex;

    /** */
    public Builder() {}

    private Builder(RadiotapDataMcs obj) {
      this.bandwidthKnown = obj.bandwidthKnown;
      this.mcsIndexKnown = obj.mcsIndexKnown;
      this.guardIntervalKnown = obj.guardIntervalKnown;
      this.htFormatKnown = obj.htFormatKnown;
      this.fecTypeKnown = obj.fecTypeKnown;
      this.stbcKnown = obj.stbcKnown;
      this.nessKnown = obj.nessKnown;
      this.nessMsb = obj.nessMsb;
      this.bandwidth = obj.bandwidth;
      this.shortGuardInterval = obj.shortGuardInterval;
      this.htFormat = obj.htFormat;
      this.fecType = obj.fecType;
      this.numStbcStreams = obj.numStbcStreams;
      this.nessLsb = obj.nessLsb;
      this.mcsRateIndex = obj.mcsRateIndex;
    }

    /**
     * @param bandwidthKnown bandwidthKnown
     * @return this Builder object for method chaining.
     */
    public Builder bandwidthKnown(boolean bandwidthKnown) {
      this.bandwidthKnown = bandwidthKnown;
      return this;
    }

    /**
     * @param mcsIndexKnown mcsIndexKnown
     * @return this Builder object for method chaining.
     */
    public Builder mcsIndexKnown(boolean mcsIndexKnown) {
      this.mcsIndexKnown = mcsIndexKnown;
      return this;
    }

    /**
     * @param guardIntervalKnown guardIntervalKnown
     * @return this Builder object for method chaining.
     */
    public Builder guardIntervalKnown(boolean guardIntervalKnown) {
      this.guardIntervalKnown = guardIntervalKnown;
      return this;
    }

    /**
     * @param htFormatKnown htFormatKnown
     * @return this Builder object for method chaining.
     */
    public Builder htFormatKnown(boolean htFormatKnown) {
      this.htFormatKnown = htFormatKnown;
      return this;
    }

    /**
     * @param fecTypeKnown fecTypeKnown
     * @return this Builder object for method chaining.
     */
    public Builder fecTypeKnown(boolean fecTypeKnown) {
      this.fecTypeKnown = fecTypeKnown;
      return this;
    }

    /**
     * @param stbcKnown stbcKnown
     * @return this Builder object for method chaining.
     */
    public Builder stbcKnown(boolean stbcKnown) {
      this.stbcKnown = stbcKnown;
      return this;
    }

    /**
     * @param nessKnown nessKnown
     * @return this Builder object for method chaining.
     */
    public Builder nessKnown(boolean nessKnown) {
      this.nessKnown = nessKnown;
      return this;
    }

    /**
     * @param nessMsb nessMsb
     * @return this Builder object for method chaining.
     */
    public Builder nessMsb(boolean nessMsb) {
      this.nessMsb = nessMsb;
      return this;
    }

    /**
     * @param bandwidth bandwidth
     * @return this Builder object for method chaining.
     */
    public Builder bandwidth(Bandwidth bandwidth) {
      this.bandwidth = bandwidth;
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

    /**
     * @param htFormat htFormat
     * @return this Builder object for method chaining.
     */
    public Builder htFormat(HtFormat htFormat) {
      this.htFormat = htFormat;
      return this;
    }

    /**
     * @param fecType fecType
     * @return this Builder object for method chaining.
     */
    public Builder fecType(RadiotapFecType fecType) {
      this.fecType = fecType;
      return this;
    }

    /**
     * @param numStbcStreams numStbcStreams
     * @return this Builder object for method chaining.
     */
    public Builder numStbcStreams(byte numStbcStreams) {
      this.numStbcStreams = numStbcStreams;
      return this;
    }

    /**
     * @param nessLsb nessLsb
     * @return this Builder object for method chaining.
     */
    public Builder nessLsb(boolean nessLsb) {
      this.nessLsb = nessLsb;
      return this;
    }

    /**
     * @param mcsRateIndex mcsRateIndex
     * @return this Builder object for method chaining.
     */
    public Builder mcsRateIndex(byte mcsRateIndex) {
      this.mcsRateIndex = mcsRateIndex;
      return this;
    }

    /** @return a new RadiotapMcs object. */
    public RadiotapDataMcs build() {
      return new RadiotapDataMcs(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static enum Bandwidth {

    /** 20 */
    BW_20(0, "20"),

    /** 40 */
    BW_40(1, "40"),

    /** 20L */
    BW_20L(2, "20L"),

    /** 20U */
    BW_20U(3, "20U");

    private final int value;
    private final String name;

    private Bandwidth(int value, String name) {
      this.value = value;
      this.name = name;
    }

    /** @return value */
    public int getValue() {
      return value;
    }

    /** @return name */
    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static enum HtFormat {

    /** mixed */
    MIXED(0),

    /** greenfield */
    GREENFIELD(1);

    private final int value;

    private HtFormat(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
