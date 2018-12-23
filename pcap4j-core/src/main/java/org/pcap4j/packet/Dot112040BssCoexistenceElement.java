/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 20/40 BSS Coexistence element
 *
 * <pre style="white-space: pre;">
 *         1                 1                  1
 * +-----------------+-----------------+-----------------+
 * |   Element ID    |     Length      |Information field|
 * +-----------------+-----------------+-----------------+
 * Element ID: 72
 * </pre>
 *
 * The 20/40 BSS Coexistence element is used by STAs to exchange information that affects 20/40 BSS
 * coexistence. The structure of the 20/40 BSS Coexistence Information field is as follows:
 *
 * <pre style="white-space: pre;">
 *       B0            B1            B2            B3            B4          B5,6,7
 * +-------------+-------------+-------------+-------------+-------------+-------------+
 * |Information  |Forty MHz    |20 MHz BSS   |OBSS Scanning|OBSS Scanning|  Reserved   |
 * |Request      |Intolerant   |Width Request|Exemption    |Exemption    |             |
 * |             |             |             |Request      |Grant        |             |
 * +-------------+-------------+-------------+-------------+-------------+-------------+
 * </pre>
 *
 * The Information Request field is used to indicate that a transmitting STA is requesting the
 * recipient to transmit a 20/40 BSS Coexistence Management frame with the transmitting STA as the
 * recipient. The Forty MHz Intolerant field is set to 1 to prohibit an AP that receives this
 * information or reports of this information from operating a 20/40 MHz BSS. When equal to 0, it
 * does not prohibit a receiving AP from operating a 20/40 MHz BSS. This field is used for inter-BSS
 * communication. The definition of this field is the same as the definition of the Forty MHz
 * Intolerant field in the HT Capabilities element. The 20 MHz BSS Width Request field is set to 1
 * to prohibit a receiving AP from operating its BSS as a 20/40 MHz BSS. Otherwise, it is set to 0.
 * This field is used for intra-BSS communication. The OBSS Scanning Exemption Request field is set
 * to 1 to indicate that the transmitting non-AP STA is requesting the BSS to allow the STA to be
 * exempt from OBSS scanning. Otherwise, it is set to 0. The OBSS Scanning Exemption Request field
 * is reserved when transmitted by an AP. The OBSS Scanning Exemption Request field is reserved when
 * a 20/40 BSS Coexistence element is included in a group addressed frame. The OBSS Scanning
 * Exemption Grant field is set to 1 by an AP to indicate that the receiving STA is exempted from
 * performing OBSS Scanning. Otherwise, it is set to 0. The OBSS Scanning Exemption Grant field is
 * reserved when transmitted by a non-AP STA. The OBSS Scanning Exemption Grant field is reserved
 * when a 20/40 BSS Coexistence element is included in a group addressed frame.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot112040BssCoexistenceElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 8883468584264617141L;

  private final boolean informationRequested;
  private final boolean fortyMhzIntolerant;
  private final boolean twentyMhzBssWidthRequested;
  private final boolean obssScanningExemptionRequested;
  private final boolean obssScanningExemptionGranted;
  private final boolean bit5;
  private final boolean bit6;
  private final boolean bit7;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot112040BssCoexistenceElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot112040BssCoexistenceElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot112040BssCoexistenceElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot112040BssCoexistenceElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.IE_20_40_BSS_COEXISTENCE);

    if (getLengthAsInt() != 1) {
      throw new IllegalRawDataException(
          "The length must be 1 but is actually: " + getLengthAsInt());
    }

    this.informationRequested = (rawData[offset + 2] & 0x01) != 0;
    this.fortyMhzIntolerant = (rawData[offset + 2] & 0x02) != 0;
    this.twentyMhzBssWidthRequested = (rawData[offset + 2] & 0x04) != 0;
    this.obssScanningExemptionRequested = (rawData[offset + 2] & 0x08) != 0;
    this.obssScanningExemptionGranted = (rawData[offset + 2] & 0x10) != 0;
    this.bit5 = (rawData[offset + 2] & 0x20) != 0;
    this.bit6 = (rawData[offset + 2] & 0x40) != 0;
    this.bit7 = (rawData[offset + 2] & 0x80) != 0;
  }

  /** @param builder builder */
  private Dot112040BssCoexistenceElement(Builder builder) {
    super(builder);
    this.informationRequested = builder.informationRequested;
    this.fortyMhzIntolerant = builder.fortyMhzIntolerant;
    this.twentyMhzBssWidthRequested = builder.twentyMhzBssWidthRequested;
    this.obssScanningExemptionRequested = builder.obssScanningExemptionRequested;
    this.obssScanningExemptionGranted = builder.obssScanningExemptionGranted;
    this.bit5 = builder.bit5;
    this.bit6 = builder.bit6;
    this.bit7 = builder.bit7;
  }

  /** @return true if the Information Request field is set to 1; otherwise false. */
  public boolean isInformationRequested() {
    return informationRequested;
  }

  /** @return true if the Forty MHz Intolerant field is set to 1; otherwise false. */
  public boolean is40MhzIntolerant() {
    return fortyMhzIntolerant;
  }

  /** @return true if the 20 MHz BSS Width Request field is set to 1; otherwise false. */
  public boolean is20MhzBssWidthRequested() {
    return twentyMhzBssWidthRequested;
  }

  /** @return true if the OBSS Scanning Exemption Request field is set to 1; otherwise false. */
  public boolean isObssScanningExemptionRequested() {
    return obssScanningExemptionRequested;
  }

  /** @return true if the OBSS Scanning Exemption Grant field is set to 1; otherwise false. */
  public boolean isObssScanningExemptionGranted() {
    return obssScanningExemptionGranted;
  }

  /** @return true if the bit 5 of the Information field is set to 1; otherwise false. */
  public boolean getBit5() {
    return bit5;
  }

  /** @return true if the bit 6 of the Information field is set to 1; otherwise false. */
  public boolean getBit6() {
    return bit6;
  }

  /** @return true if bit 7 of the Information field is set to 1; otherwise false. */
  public boolean getBit7() {
    return bit7;
  }

  @Override
  public int length() {
    return 3;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[3];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    if (informationRequested) {
      rawData[2] |= 0x01;
    }
    if (fortyMhzIntolerant) {
      rawData[2] |= 0x02;
    }
    if (twentyMhzBssWidthRequested) {
      rawData[2] |= 0x04;
    }
    if (obssScanningExemptionRequested) {
      rawData[2] |= 0x08;
    }
    if (obssScanningExemptionGranted) {
      rawData[2] |= 0x10;
    }
    if (bit5) {
      rawData[2] |= 0x20;
    }
    if (bit6) {
      rawData[2] |= 0x40;
    }
    if (bit7) {
      rawData[2] |= 0x80;
    }
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + (bit5 ? 1231 : 1237);
    result = prime * result + (bit6 ? 1231 : 1237);
    result = prime * result + (bit7 ? 1231 : 1237);
    result = prime * result + (fortyMhzIntolerant ? 1231 : 1237);
    result = prime * result + (informationRequested ? 1231 : 1237);
    result = prime * result + (obssScanningExemptionGranted ? 1231 : 1237);
    result = prime * result + (obssScanningExemptionRequested ? 1231 : 1237);
    result = prime * result + (twentyMhzBssWidthRequested ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot112040BssCoexistenceElement other = (Dot112040BssCoexistenceElement) obj;
    if (fortyMhzIntolerant != other.fortyMhzIntolerant) return false;
    if (informationRequested != other.informationRequested) return false;
    if (obssScanningExemptionGranted != other.obssScanningExemptionGranted) return false;
    if (obssScanningExemptionRequested != other.obssScanningExemptionRequested) return false;
    if (twentyMhzBssWidthRequested != other.twentyMhzBssWidthRequested) return false;
    if (bit5 != other.bit5) return false;
    if (bit6 != other.bit6) return false;
    if (bit7 != other.bit7) return false;
    return true;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return the string representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent).append("20/40 BSS Coexistence:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent).append("  Information Requested: ").append(informationRequested).append(ls);
    sb.append(indent).append("  40 MHz Intolerant: ").append(fortyMhzIntolerant).append(ls);
    sb.append(indent)
        .append("  20 MHz BSS Width Requested: ")
        .append(twentyMhzBssWidthRequested)
        .append(ls);
    sb.append(indent)
        .append("  OBSS Scanning Exemption Requested: ")
        .append(obssScanningExemptionRequested)
        .append(ls);
    sb.append(indent)
        .append("  OBSS Scanning Exemption Granted: ")
        .append(obssScanningExemptionGranted)
        .append(ls);
    sb.append(indent).append("  Bit 5: ").append(bit5).append(ls);
    sb.append(indent).append("  Bit 6: ").append(bit6).append(ls);
    sb.append(indent).append("  Bit 7: ").append(bit7).append(ls);

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private boolean informationRequested;
    private boolean fortyMhzIntolerant;
    private boolean twentyMhzBssWidthRequested;
    private boolean obssScanningExemptionRequested;
    private boolean obssScanningExemptionGranted;
    private boolean bit5;
    private boolean bit6;
    private boolean bit7;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(
              Dot11InformationElementId.IE_20_40_BSS_COEXISTENCE.value()));
    }

    /** @param elem a Dot112040BssCoexistenceElement object. */
    private Builder(Dot112040BssCoexistenceElement elem) {
      super(elem);
      this.informationRequested = elem.informationRequested;
      this.fortyMhzIntolerant = elem.fortyMhzIntolerant;
      this.twentyMhzBssWidthRequested = elem.twentyMhzBssWidthRequested;
      this.obssScanningExemptionRequested = elem.obssScanningExemptionRequested;
      this.obssScanningExemptionGranted = elem.obssScanningExemptionGranted;
      this.bit5 = elem.bit5;
      this.bit6 = elem.bit6;
      this.bit7 = elem.bit7;
    }

    /**
     * @param informationRequested informationRequested
     * @return this Builder object for method chaining.
     */
    public Builder informationRequested(boolean informationRequested) {
      this.informationRequested = informationRequested;
      return this;
    }

    /**
     * @param fortyMhzIntolerant fortyMhzIntolerant
     * @return this Builder object for method chaining.
     */
    public Builder fortyMhzIntolerant(boolean fortyMhzIntolerant) {
      this.fortyMhzIntolerant = fortyMhzIntolerant;
      return this;
    }

    /**
     * @param twentyMhzBssWidthRequested twentyMhzBssWidthRequested
     * @return this Builder object for method chaining.
     */
    public Builder twentyMhzBssWidthRequested(boolean twentyMhzBssWidthRequested) {
      this.twentyMhzBssWidthRequested = twentyMhzBssWidthRequested;
      return this;
    }

    /**
     * @param obssScanningExemptionRequested obssScanningExemptionRequested
     * @return this Builder object for method chaining.
     */
    public Builder obssScanningExemptionRequested(boolean obssScanningExemptionRequested) {
      this.obssScanningExemptionRequested = obssScanningExemptionRequested;
      return this;
    }

    /**
     * @param obssScanningExemptionGranted obssScanningExemptionGranted
     * @return this Builder object for method chaining.
     */
    public Builder obssScanningExemptionGranted(boolean obssScanningExemptionGranted) {
      this.obssScanningExemptionGranted = obssScanningExemptionGranted;
      return this;
    }

    /**
     * @param bit5 bit5
     * @return this Builder object for method chaining.
     */
    public Builder bit5(boolean bit5) {
      this.bit5 = bit5;
      return this;
    }

    /**
     * @param bit6 bit6
     * @return this Builder object for method chaining.
     */
    public Builder bit6(boolean bit6) {
      this.bit6 = bit6;
      return this;
    }

    /**
     * @param bit7 bit7
     * @return this Builder object for method chaining.
     */
    public Builder bit7(boolean bit7) {
      this.bit7 = bit7;
      return this;
    }

    @Override
    public Builder length(byte length) {
      super.length(length);
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      super.correctLengthAtBuild(correctLengthAtBuild);
      return this;
    }

    @Override
    public Dot112040BssCoexistenceElement build() {
      if (getCorrectLengthAtBuild()) {
        length((byte) 1);
      }
      return new Dot112040BssCoexistenceElement(this);
    }
  }
}
