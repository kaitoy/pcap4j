/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import org.pcap4j.util.ByteArrays;

/**
 * Link Adaptation Control field of an IEEE802.11 frame.
 *
 * <pre>{@code
 *      0        1        2        3        4        5        6        7
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * |VHT_MFB |  TRQ   |                MAI                |       MFSI      |
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * |  MFSI  |                           MFB/ASELC                          |
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11LinkAdaptationControl implements Serializable {

  /** */
  private static final long serialVersionUID = 7735461000002622072L;

  /** ASELI */
  public static final byte ASELI = 14;

  private final boolean vhtMfb;
  private final boolean trq;
  private final boolean aseli;
  private final Mai mai;
  private final byte mfsi;
  private final Byte mfb;
  private final Aselc aselc;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11LinkAdaptationControl object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11LinkAdaptationControl newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11LinkAdaptationControl(rawData, offset, length);
  }

  private Dot11LinkAdaptationControl(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a Dot11LinkAdaptationControl (")
          .append(2)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    byte first = rawData[offset];
    byte second = rawData[offset + 1];
    this.vhtMfb = (first & 0x01) != 0;
    this.trq = (first & 0x02) != 0;
    this.aseli = ((first >> 2) & 0x0F) == ASELI;
    if (aseli) {
      this.mai = null;
    } else {
      this.mai = new Mai((first & 0x04) != 0, (byte) ((first >> 3) & 0x07));
    }
    this.mfsi = (byte) (((first >> 6) & 0x03) | ((second & 0x01) << 2));

    byte mfbAselc = (byte) ((second >> 1) & 0x7F);
    this.mfb = mfbAselc;
    this.aselc = new Aselc(mfbAselc);
  }

  private Dot11LinkAdaptationControl(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }
    if ((builder.maiOrAseli & 0xF0) != 0) {
      throw new IllegalArgumentException(
          "(builder.maiOrAseli & 0xF0) must be zero. builder.maiOrAseli: " + builder.maiOrAseli);
    }
    if ((builder.mfsi & 0xF8) != 0) {
      throw new IllegalArgumentException(
          "(builder.mfsi & 0xF8) must be zero. builder.mfsi: " + builder.mfsi);
    }
    if ((builder.mfbOrAselc & 0x80) != 0) {
      throw new IllegalArgumentException(
          "(builder.mfbOrAselc & 0x80) must be zero. builder.mfbOrAselc: " + builder.mfbOrAselc);
    }

    this.vhtMfb = builder.vhtMfb;
    this.trq = builder.trq;
    this.aseli = builder.maiOrAseli == ASELI;
    if (aseli) {
      this.mai = null;
    } else {
      this.mai = new Mai(builder.maiOrAseli);
    }
    this.mfsi = builder.mfsi;
    this.mfb = builder.mfbOrAselc;
    this.aselc = new Aselc(builder.mfbOrAselc);
  }

  /** @return true if the VHT_MFB field is set to 1; false otherwise. */
  public boolean isVhtMfb() {
    return vhtMfb;
  }

  /** @return true if the TRQ field is set to 1; false otherwise. */
  public boolean isTrq() {
    return trq;
  }

  /**
   * @return true if the MAI field is set to 14 (ASELI); false otherwise.
   * @see #ASELI
   */
  public boolean isAselIndicated() {
    return aseli;
  }

  /**
   * @return a {@link Mai} object if {@link #isAselIndicated() isAselIndicated} returns false;
   *     otherwise null.
   */
  public Mai getMai() {
    return mai;
  }

  /** @return mfsi */
  public byte getMfsi() {
    return mfsi;
  }

  /** @return mfsi */
  public int getMfsiAsInt() {
    return mfsi;
  }

  /**
   * @return the value of MFB if {@link #isAselIndicated() isAselIndicated} returns false; otherwise
   *     null.
   */
  public Byte getMfb() {
    if (aseli) {
      return null;
    } else {
      return mfb;
    }
  }

  /**
   * @return the value of MFB if {@link #isAselIndicated() isAselIndicated} returns false; otherwise
   *     null.
   */
  public Integer getMfbAsInteger() {
    if (aseli) {
      return null;
    } else {
      return (int) mfb;
    }
  }

  /**
   * @return an {@link Aselc} object if {@link #isAselIndicated() isAselIndicated} returns true;
   *     otherwise null.
   */
  public Aselc getAselc() {
    if (aseli) {
      return aselc;
    } else {
      return null;
    }
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[2];

    byte maiOrAseli = aseli ? ASELI : mai.getRawData();
    data[0] = (byte) ((mfsi << 6) | maiOrAseli << 2);
    if (trq) {
      data[0] |= 0x02;
    }
    if (vhtMfb) {
      data[0] |= 0x01;
    }
    data[1] = (byte) (mfb << 1);
    if ((mfsi & 0x04) != 0) {
      data[1] |= 0x01;
    }

    return data;
  }

  /** @return length */
  public int length() {
    return 2;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(250);

    sb.append("[VHT_MFB: ")
        .append(vhtMfb)
        .append(", TRQ: ")
        .append(trq)
        .append(", ASELI: ")
        .append(aseli);

    if (!aseli) {
      sb.append(", MAI: ").append(mai);
    }
    sb.append(", MFSI: ").append(mfsi);
    if (aseli) {
      sb.append(", ASELC: ").append(aselc);
    } else {
      sb.append(", MFB: ").append(mfb);
    }
    sb.append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((mai == null) ? 0 : mai.hashCode());
    result = prime * result + mfb.hashCode();
    result = prime * result + mfsi;
    result = prime * result + (aseli ? 1231 : 1237);
    result = prime * result + (vhtMfb ? 1231 : 1237);
    result = prime * result + (trq ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11LinkAdaptationControl other = (Dot11LinkAdaptationControl) obj;
    if (mai == null) {
      if (other.mai != null) return false;
    } else if (!mai.equals(other.mai)) return false;
    if (!mfb.equals(other.mfb)) return false;
    if (mfsi != other.mfsi) return false;
    if (aseli != other.aseli) return false;
    if (vhtMfb != other.vhtMfb) return false;
    if (trq != other.trq) return false;
    return true;
  }

  /**
   * MAI subfield
   *
   * <pre style="white-space: pre;">
   *   0   1   2   3
   * +---+---+---+---+
   * |MRQ|    MSI    |
   * +---+---+---+---+
   * </pre>
   *
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Mai implements Serializable {

    /** */
    private static final long serialVersionUID = -7417614720576047794L;

    private final boolean mrq;
    private final byte msi;

    /**
     * @param mrq mrq
     * @param msi msi
     */
    public Mai(boolean mrq, byte msi) {
      if (msi < 0 || msi > 6) {
        throw new IllegalArgumentException("msi must be between 0 and 6 but is actually: " + msi);
      }
      this.mrq = mrq;
      this.msi = msi;
    }

    /** @param rawData the raw data which the MRQ is encoded at the LSB. */
    public Mai(byte rawData) {
      this.mrq = (rawData & 0x01) != 0;
      this.msi = (byte) ((rawData >> 1) & 0x07);
    }

    /** @return mrq */
    public boolean isMrq() {
      return mrq;
    }

    /** @return msi */
    public byte getMsi() {
      return msi;
    }

    /** @return the raw data */
    public byte getRawData() {
      if (mrq) {
        return (byte) ((msi << 1) | 1);
      } else {
        return (byte) (msi << 1);
      }
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(250);

      sb.append("[MRQ: ").append(mrq).append(", MSI: ").append(msi).append("]");

      return sb.toString();
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + (mrq ? 1231 : 1237);
      result = prime * result + msi;
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      Mai other = (Mai) obj;
      if (mrq != other.mrq) return false;
      if (msi != other.msi) return false;
      return true;
    }
  }

  /**
   * ASELC subfield
   *
   * <pre style="white-space: pre;">
   *    0    1    2    3    4    5
   * +----+----+----+----+----+----+----+
   * | ASEL Command |     ASEL Data     |
   * +----+----+----+----+----+----+----+
   * </pre>
   *
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Aselc implements Serializable {

    /** */
    private static final long serialVersionUID = -5404846090809709793L;

    private final AselCommand command;
    private final byte data;

    /**
     * @param command command
     * @param data data
     */
    public Aselc(AselCommand command, byte data) {
      if (command == null) {
        throw new IllegalArgumentException("command is null.");
      }
      if ((data & 0xF0) != 0) {
        throw new IllegalArgumentException("(data & 0xF0) must be zero. data: " + data);
      }
      this.command = command;
      this.data = data;
    }

    /** @param rawData the raw data which the ASEL Command is encoded in 3 bits from the LSB. */
    public Aselc(byte rawData) {
      this.command = AselCommand.getInstance(rawData & 0x07);
      this.data = (byte) ((rawData >> 3) & 0x0F);
    }

    /** @return command */
    public AselCommand getCommand() {
      return command;
    }

    /** @return data */
    public byte getData() {
      return data;
    }

    /** @return the raw data. */
    public byte getRawData() {
      return (byte) ((command.value << 4) | (data));
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + command.hashCode();
      result = prime * result + data;
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      Aselc other = (Aselc) obj;
      if (command != other.command) return false;
      if (data != other.data) return false;
      return true;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder(250);

      sb.append("[ASEL Command: ").append(command).append(", ASEL Data: ").append(data).append("]");

      return sb.toString();
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum AselCommand {

    /** Transmit Antenna Selection Sounding Indication (TXASSI): 0 */
    TXASSI(0, "TXASSI"),

    /**
     * Transmit Antenna Selection Sounding Request (TXASSR) or Transmit ASEL Sounding Resumption: 1
     */
    TXASSR(1, "TXASSR"),

    /** Receive Antenna Selection Sounding Indication (RXASSI): 2 */
    RXASSI(2, "RXASSI"),

    /** Receive Antenna Selection Sounding Request (RXASSR): 3 */
    RXASSR(3, "RXASSR"),

    /** Sounding Label: 4 */
    SOUNDING_LABEL(4, "Sounding Label"),

    /** No Feedback Due to ASEL Training Failure or Stale Feedback: 5 */
    NO_FEEDBACK(5, "No Feedback"),

    /**
     * Transmit Antenna Selection Sounding Indication requesting feedback of explicit CSI
     * (TXASSI-CSI): 6
     */
    TXASSI_CSI(6, "TXASSI-CSI"),

    /** Reserved: 7 */
    SEVEN(7, "Reserved");

    private final int value;
    private final String name;

    private AselCommand(int value, String name) {
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
      StringBuilder sb = new StringBuilder(50);
      sb.append(value).append(" (").append(name).append(")");
      return sb.toString();
    }

    /**
     * @param value value
     * @return the AselCommand object the value of which is the given value.
     */
    public static AselCommand getInstance(int value) {
      for (AselCommand com : values()) {
        if (com.value == value) {
          return com;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder {

    private boolean vhtMfb;
    private boolean trq;
    private byte maiOrAseli;
    private byte mfsi;
    private byte mfbOrAselc;

    /** */
    public Builder() {}

    private Builder(Dot11LinkAdaptationControl obj) {
      this.vhtMfb = obj.vhtMfb;
      this.trq = obj.trq;
      this.maiOrAseli = obj.mai.getRawData();
      this.mfsi = obj.mfsi;
      this.mfbOrAselc = obj.mfb;
    }

    /**
     * @param vhtMfb vhtMfb
     * @return this Builder object for method chaining.
     */
    public Builder vhtMfb(boolean vhtMfb) {
      this.vhtMfb = vhtMfb;
      return this;
    }

    /**
     * @param trq trq
     * @return this Builder object for method chaining.
     */
    public Builder trq(boolean trq) {
      this.trq = trq;
      return this;
    }

    /**
     * @param maiOrAseli maiOrAseli
     * @return this Builder object for method chaining.
     * @see #ASELI
     */
    public Builder maiOrAseli(byte maiOrAseli) {
      this.maiOrAseli = maiOrAseli;
      return this;
    }

    /**
     * @param maiOrAseli maiOrAseli
     * @return this Builder object for method chaining.
     */
    public Builder maiOrAseli(Mai maiOrAseli) {
      this.maiOrAseli = maiOrAseli.getRawData();
      return this;
    }

    /**
     * @param mfsi mfsi
     * @return this Builder object for method chaining.
     */
    public Builder mfsi(byte mfsi) {
      this.mfsi = mfsi;
      return this;
    }

    /**
     * @param mfbOrAselc mfbOrAselc
     * @return this Builder object for method chaining.
     */
    public Builder mfbOrAselc(byte mfbOrAselc) {
      this.mfbOrAselc = mfbOrAselc;
      return this;
    }

    /**
     * @param mfbOrAselc mfbOrAselc
     * @return this Builder object for method chaining.
     */
    public Builder mfbOrAselc(Aselc mfbOrAselc) {
      this.mfbOrAselc = mfbOrAselc.getRawData();
      return this;
    }

    /** @return a new Dot11LinkAdaptationControl object. */
    public Dot11LinkAdaptationControl build() {
      return new Dot11LinkAdaptationControl(this);
    }
  }
}
