/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Vendor Specific element
 *
 * <pre style="white-space: pre;">
 *       1         1            variable          variable
 * +------------+------------+------------+------------------------
 * | Element ID |   Length   |Organization|Vendor-specific content
 * |            |            |Identifier  |
 * +------------+------------+------------+------------------------
 * Element ID: 221
 * </pre>
 *
 * The Vendor Specific element is used to carry information not defined in this standard within a
 * single defined format, so that reserved element IDs are not usurped for nonstandard purposes and
 * so that interoperability is more easily achieved in the presence of nonstandard information. The
 * element requires that the first 3 or more octets of the Information field identify the entity
 * that has defined the content of the particular Vendor Specific element.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11VendorSpecificElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 2095272309443428672L;

  private final byte[] information;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11VendorSpecificElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11VendorSpecificElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11VendorSpecificElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11VendorSpecificElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.VENDOR_SPECIFIC);
    int infoLen = getLengthAsInt();
    if (infoLen == 0) {
      this.information = new byte[0];
    } else {
      this.information = ByteArrays.getSubArray(rawData, offset + 2, infoLen);
    }
  }

  /** @param builder builder */
  private Dot11VendorSpecificElement(Builder builder) {
    super(builder);

    if (builder.information.length > 255) {
      throw new IllegalArgumentException("Too long information: " + builder.information);
    }

    this.information = ByteArrays.clone(builder.information);
  }

  /** @return information */
  public byte[] getInformation() {
    return ByteArrays.clone(information);
  }

  @Override
  public int length() {
    return 2 + information.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    System.arraycopy(information, 0, rawData, 2, information.length);
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
    result = prime * result + Arrays.hashCode(information);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11VendorSpecificElement other = (Dot11VendorSpecificElement) obj;
    if (!Arrays.equals(information, other.information)) return false;
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

    sb.append(indent).append("Vendor Specific:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent)
        .append("  Information: 0x")
        .append(ByteArrays.toHexString(information, ""))
        .append(ls);

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private byte[] information;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(Dot11InformationElementId.VENDOR_SPECIFIC.value()));
    }

    /** @param elem a Dot11VendorSpecificElement object. */
    private Builder(Dot11VendorSpecificElement elem) {
      super(elem);
      this.information = elem.information;
    }

    /**
     * @param information information
     * @return this Builder object for method chaining.
     */
    public Builder information(byte[] information) {
      this.information = information;
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
    public Dot11VendorSpecificElement build() {
      if (information == null) {
        throw new NullPointerException("information is null.");
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) information.length);
      }
      return new Dot11VendorSpecificElement(this);
    }
  }
}
