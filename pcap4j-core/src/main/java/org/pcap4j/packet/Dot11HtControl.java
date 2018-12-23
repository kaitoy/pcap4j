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
 * HT Control field of an IEEE802.11 frame.
 *
 * <pre style="white-space: pre;">
 *      0          1          2          3          4          5          6          7
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * |                                                                                       |
 * |                                                                                       |
 * +                              Link Adaptation Control                                  +
 * |                                                                                       |
 * |                                                                                       |
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * |    Calibration      |     Calibration     |      Reserved       |    CSI/Steering     |
 * |    Position         |     Sequence        |                     |                     |
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * |NDP Annou-|                       Reserved                       |AC        |RDG/More  |
 * |ncement   |                                                      |Constraint|PPDU      |
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * </pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11HtControl implements Serializable {

  /** */
  private static final long serialVersionUID = 8919536873635707080L;

  private final Dot11LinkAdaptationControl linkAdaptationControl;
  private final CalibrationPosition calibrationPosition;
  private final byte calibrationSequence;
  private final boolean bit20;
  private final boolean bit21;
  private final CsiOrSteering csiOrSteering;
  private final boolean ndpAnnouncement;
  private final boolean bit25;
  private final boolean bit26;
  private final boolean bit27;
  private final boolean bit28;
  private final boolean bit29;
  private final boolean acConstraint;
  private final boolean rdgOrMorePpdu;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11HtControl object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11HtControl newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11HtControl(rawData, offset, length);
  }

  private Dot11HtControl(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a Dot11HtControl (")
          .append(2)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.linkAdaptationControl = Dot11LinkAdaptationControl.newInstance(rawData, offset, 2);

    byte data = rawData[offset + 2];
    this.calibrationPosition = CalibrationPosition.getInstance(data & 0x03);
    this.calibrationSequence = (byte) ((data >> 2) & 0x03);
    this.bit20 = (data & 0x10) != 0;
    this.bit21 = (data & 0x20) != 0;
    this.csiOrSteering = CsiOrSteering.getInstance((data >> 6) & 0x03);

    data = rawData[offset + 3];
    this.ndpAnnouncement = (data & 0x01) != 0;
    this.bit25 = (data & 0x02) != 0;
    this.bit26 = (data & 0x04) != 0;
    this.bit27 = (data & 0x08) != 0;
    this.bit28 = (data & 0x10) != 0;
    this.bit29 = (data & 0x20) != 0;
    this.acConstraint = (data & 0x40) != 0;
    this.rdgOrMorePpdu = (data & 0x80) != 0;
  }

  private Dot11HtControl(Builder builder) {
    if (builder == null
        || builder.linkAdaptationControl == null
        || builder.calibrationPosition == null
        || builder.csiOrSteering == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.linkAdaptationControl: ")
          .append(builder.linkAdaptationControl)
          .append(" builder.calibrationPosition: ")
          .append(builder.calibrationPosition)
          .append(" builder.csiOrSteering: ")
          .append(builder.csiOrSteering);
      throw new NullPointerException(sb.toString());
    }

    if ((builder.calibrationSequence & 0xFC) != 0) {
      StringBuilder sb = new StringBuilder(150);
      sb.append("(builder.calibrationSequence & 0xFC) must be zero.")
          .append(" builder.calibrationSequence: ")
          .append(builder.calibrationSequence);
      throw new IllegalArgumentException(sb.toString());
    }

    this.linkAdaptationControl = builder.linkAdaptationControl;
    this.calibrationPosition = builder.calibrationPosition;
    this.calibrationSequence = builder.calibrationSequence;
    this.bit20 = builder.bit20;
    this.bit21 = builder.bit21;
    this.csiOrSteering = builder.csiOrSteering;
    this.ndpAnnouncement = builder.ndpAnnouncement;
    this.bit25 = builder.bit25;
    this.bit26 = builder.bit26;
    this.bit27 = builder.bit27;
    this.bit28 = builder.bit28;
    this.bit29 = builder.bit29;
    this.acConstraint = builder.acConstraint;
    this.rdgOrMorePpdu = builder.rdgOrMorePpdu;
  }

  /** @return linkAdaptationControl */
  public Dot11LinkAdaptationControl getLinkAdaptationControl() {
    return linkAdaptationControl;
  }

  /** @return calibrationPosition */
  public CalibrationPosition getCalibrationPosition() {
    return calibrationPosition;
  }

  /** @return calibrationSequence */
  public byte getCalibrationSequence() {
    return calibrationSequence;
  }

  /** @return calibrationSequence */
  public int getCalibrationSequenceAsInt() {
    return calibrationSequence;
  }

  /** @return true if the bit 20 is set to 1; false otherwise. */
  public boolean getBit20() {
    return bit20;
  }

  /** @return true if the bit 21 is set to 1; false otherwise. */
  public boolean getBit21() {
    return bit21;
  }

  /** @return csiOrSteering */
  public CsiOrSteering getCsiOrSteering() {
    return csiOrSteering;
  }

  /** @return true if the NDP Announcement field is set to 1; false otherwise. */
  public boolean getNdpAnnouncement() {
    return ndpAnnouncement;
  }

  /** @return true if the bit 25 is set to 1; false otherwise. */
  public boolean getBit25() {
    return bit25;
  }

  /** @return true if the bit 26 is set to 1; false otherwise. */
  public boolean getBit26() {
    return bit26;
  }

  /** @return true if the bit 27 is set to 1; false otherwise. */
  public boolean getBit27() {
    return bit27;
  }

  /** @return true if the bit 28 is set to 1; false otherwise. */
  public boolean getBit28() {
    return bit28;
  }

  /** @return true if the bit 29 is set to 1; false otherwise. */
  public boolean getBit29() {
    return bit29;
  }

  /** @return true if the AC Constraint field is set to 1; false otherwise. */
  public boolean getAcConstraint() {
    return acConstraint;
  }

  /** @return true if the RDG/More PPDU field is set to 1; false otherwise. */
  public boolean getRdgOrMorePpdu() {
    return rdgOrMorePpdu;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[length()];

    System.arraycopy(linkAdaptationControl.getRawData(), 0, data, 0, 2);
    data[2] =
        (byte)
            ((csiOrSteering.value << 6) | (calibrationSequence << 2) | calibrationPosition.value);
    if (bit20) {
      data[2] |= 0x10;
    }
    if (bit21) {
      data[2] |= 0x20;
    }
    if (ndpAnnouncement) {
      data[3] |= 0x01;
    }
    if (bit25) {
      data[3] |= 0x02;
    }
    if (bit26) {
      data[3] |= 0x04;
    }
    if (bit27) {
      data[3] |= 0x08;
    }
    if (bit28) {
      data[3] |= 0x10;
    }
    if (bit29) {
      data[3] |= 0x20;
    }
    if (acConstraint) {
      data[3] |= 0x40;
    }
    if (rdgOrMorePpdu) {
      data[3] |= 0x80;
    }

    return data;
  }

  /** @return length */
  public int length() {
    return 4;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return String representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("Link Adaptation Control: ")
        .append(linkAdaptationControl)
        .append(ls)
        .append(indent)
        .append("Calibration Position: ")
        .append(calibrationPosition)
        .append(ls)
        .append(indent)
        .append("Calibration Sequence: ")
        .append(calibrationSequence)
        .append(ls)
        .append(indent)
        .append("Bit 20: ")
        .append(bit20)
        .append(ls)
        .append(indent)
        .append("Bit 21: ")
        .append(bit21)
        .append(ls)
        .append(indent)
        .append("CSI/Steering: ")
        .append(csiOrSteering)
        .append(ls)
        .append(indent)
        .append("NDP Announcement: ")
        .append(ndpAnnouncement)
        .append(ls)
        .append(indent)
        .append("Bit 25: ")
        .append(bit25)
        .append(ls)
        .append(indent)
        .append("Bit 26: ")
        .append(bit26)
        .append(ls)
        .append(indent)
        .append("Bit 27: ")
        .append(bit27)
        .append(ls)
        .append(indent)
        .append("Bit 28: ")
        .append(bit28)
        .append(ls)
        .append(indent)
        .append("Bit 29: ")
        .append(bit29)
        .append(ls)
        .append(indent)
        .append("AC Constraint: ")
        .append(acConstraint)
        .append(ls)
        .append(indent)
        .append("RDG/More PPDU: ")
        .append(rdgOrMorePpdu)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (acConstraint ? 1231 : 1237);
    result = prime * result + (bit20 ? 1231 : 1237);
    result = prime * result + (bit21 ? 1231 : 1237);
    result = prime * result + (bit25 ? 1231 : 1237);
    result = prime * result + (bit26 ? 1231 : 1237);
    result = prime * result + (bit27 ? 1231 : 1237);
    result = prime * result + (bit28 ? 1231 : 1237);
    result = prime * result + (bit29 ? 1231 : 1237);
    result = prime * result + calibrationPosition.hashCode();
    result = prime * result + calibrationSequence;
    result = prime * result + csiOrSteering.hashCode();
    result = prime * result + linkAdaptationControl.hashCode();
    result = prime * result + (ndpAnnouncement ? 1231 : 1237);
    result = prime * result + (rdgOrMorePpdu ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    Dot11HtControl other = (Dot11HtControl) obj;
    if (acConstraint != other.acConstraint) {
      return false;
    }
    if (bit20 != other.bit20) {
      return false;
    }
    if (bit21 != other.bit21) {
      return false;
    }
    if (bit25 != other.bit25) {
      return false;
    }
    if (bit26 != other.bit26) {
      return false;
    }
    if (bit27 != other.bit27) {
      return false;
    }
    if (bit28 != other.bit28) {
      return false;
    }
    if (bit29 != other.bit29) {
      return false;
    }
    if (calibrationPosition != other.calibrationPosition) {
      return false;
    }
    if (calibrationSequence != other.calibrationSequence) {
      return false;
    }
    if (csiOrSteering != other.csiOrSteering) {
      return false;
    }
    if (!linkAdaptationControl.equals(other.linkAdaptationControl)) {
      return false;
    }
    if (ndpAnnouncement != other.ndpAnnouncement) {
      return false;
    }
    if (rdgOrMorePpdu != other.rdgOrMorePpdu) {
      return false;
    }
    return true;
  }

  /**
   * Calibration Position subfield of HT Control field of an IEEE802.11 frame.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum CalibrationPosition {

    /** not a calibration frame: 0 */
    NOT_CALIBRATION(0, "not a calibration frame"),

    /** calibration start: 1 */
    CALIBRATION_START(1, "calibration start"),

    /** sounding response: 2 */
    SOUNDING_RESPONSE(2, "sounding response"),

    /** sounding complete: 3 */
    SOUNDING_COMPLETE(3, "sounding complete");

    private final int value;
    private final String name;

    private CalibrationPosition(int value, String name) {
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
     * @return the CalibrationPosition object the value of which is the given value.
     */
    public static CalibrationPosition getInstance(int value) {
      for (CalibrationPosition cp : values()) {
        if (cp.value == value) {
          return cp;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }
  }

  /**
   * CSI/Steering subfield of HT Control field of an IEEE802.11 frame.
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum CsiOrSteering {

    /** No feedback required: 0 */
    NO_FEEDBACK_REQUIRED(0, "No feedback required"),

    /** CSI: 1 */
    CSI(1, "CSI"),

    /** Noncompressed beamforming: 2 */
    NONCOMPRESSED_BEAMFORMING(2, "Noncompressed beamforming"),

    /** Compressed beamforming: 3 */
    COMPRESSED_BEAMFORMING(3, "Compressed beamforming");

    private final int value;
    private final String name;

    private CsiOrSteering(int value, String name) {
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
     * @return the CsiSteering object the value of which is the given value.
     */
    public static CsiOrSteering getInstance(int value) {
      for (CsiOrSteering val : values()) {
        if (val.value == value) {
          return val;
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

    private Dot11LinkAdaptationControl linkAdaptationControl;
    private CalibrationPosition calibrationPosition;
    private byte calibrationSequence;
    private boolean bit20;
    private boolean bit21;
    private CsiOrSteering csiOrSteering;
    private boolean ndpAnnouncement;
    private boolean bit25;
    private boolean bit26;
    private boolean bit27;
    private boolean bit28;
    private boolean bit29;
    private boolean acConstraint;
    private boolean rdgOrMorePpdu;

    /** */
    public Builder() {}

    private Builder(Dot11HtControl obj) {
      this.linkAdaptationControl = obj.linkAdaptationControl;
      this.calibrationPosition = obj.calibrationPosition;
      this.calibrationSequence = obj.calibrationSequence;
      this.bit20 = obj.bit20;
      this.bit21 = obj.bit21;
      this.csiOrSteering = obj.csiOrSteering;
      this.ndpAnnouncement = obj.ndpAnnouncement;
      this.bit25 = obj.bit25;
      this.bit26 = obj.bit26;
      this.bit27 = obj.bit27;
      this.bit28 = obj.bit28;
      this.bit29 = obj.bit29;
      this.acConstraint = obj.acConstraint;
      this.rdgOrMorePpdu = obj.rdgOrMorePpdu;
    }

    /**
     * @param linkAdaptationControl linkAdaptationControl
     * @return this Builder object for method chaining.
     */
    public Builder linkAdaptationControl(Dot11LinkAdaptationControl linkAdaptationControl) {
      this.linkAdaptationControl = linkAdaptationControl;
      return this;
    }

    /**
     * @param calibrationPosition calibrationPosition
     * @return this Builder object for method chaining.
     */
    public Builder calibrationPosition(CalibrationPosition calibrationPosition) {
      this.calibrationPosition = calibrationPosition;
      return this;
    }

    /**
     * @param calibrationSequence calibrationSequence. The value is between 0 and 3 (inclusive).
     * @return this Builder object for method chaining.
     */
    public Builder calibrationSequence(byte calibrationSequence) {
      this.calibrationSequence = calibrationSequence;
      return this;
    }

    /**
     * @param bit20 bit20
     * @return this Builder object for method chaining.
     */
    public Builder bit20(boolean bit20) {
      this.bit20 = bit20;
      return this;
    }

    /**
     * @param bit21 bit21
     * @return this Builder object for method chaining.
     */
    public Builder bit21(boolean bit21) {
      this.bit21 = bit21;
      return this;
    }

    /**
     * @param csiOrSteering csiOrSteering
     * @return this Builder object for method chaining.
     */
    public Builder csiOrSteering(CsiOrSteering csiOrSteering) {
      this.csiOrSteering = csiOrSteering;
      return this;
    }

    /**
     * @param ndpAnnouncement ndpAnnouncement
     * @return this Builder object for method chaining.
     */
    public Builder ndpAnnouncement(boolean ndpAnnouncement) {
      this.ndpAnnouncement = ndpAnnouncement;
      return this;
    }

    /**
     * @param bit25 bit25
     * @return this Builder object for method chaining.
     */
    public Builder bit25(boolean bit25) {
      this.bit25 = bit25;
      return this;
    }

    /**
     * @param bit26 bit26
     * @return this Builder object for method chaining.
     */
    public Builder bit26(boolean bit26) {
      this.bit26 = bit26;
      return this;
    }

    /**
     * @param bit27 bit27
     * @return this Builder object for method chaining.
     */
    public Builder bit27(boolean bit27) {
      this.bit27 = bit27;
      return this;
    }

    /**
     * @param bit28 bit28
     * @return this Builder object for method chaining.
     */
    public Builder bit28(boolean bit28) {
      this.bit28 = bit28;
      return this;
    }

    /**
     * @param bit29 bit29
     * @return this Builder object for method chaining.
     */
    public Builder bit29(boolean bit29) {
      this.bit29 = bit29;
      return this;
    }

    /**
     * @param acConstraint acConstraint
     * @return this Builder object for method chaining.
     */
    public Builder acConstraint(boolean acConstraint) {
      this.acConstraint = acConstraint;
      return this;
    }

    /**
     * @param rdgOrMorePpdu rdgOrMorePpdu
     * @return this Builder object for method chaining.
     */
    public Builder rdgOrMorePpdu(boolean rdgOrMorePpdu) {
      this.rdgOrMorePpdu = rdgOrMorePpdu;
      return this;
    }

    /** @return a new Dot11HtControl object. */
    public Dot11HtControl build() {
      return new Dot11HtControl(this);
    }
  }
}
