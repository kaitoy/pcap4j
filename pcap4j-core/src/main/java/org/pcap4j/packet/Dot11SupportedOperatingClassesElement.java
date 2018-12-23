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
 * IEEE802.11 Supported Operating Classes element
 *
 * <pre style="white-space: pre;">
 *             1                       1                       1                   1-252
 * +-----------------------+-----------------------+-----------------------+-------------------
 * |      Element ID       |        Length         |Current Operating Class| Operating Classes
 * +-----------------------+-----------------------+-----------------------+-------------------
 * Element ID: 59
 * </pre>
 *
 * The Supported Operating Classes element is used by a STA to advertise the operating classes that
 * it is capable of operating with in this country. The value of the Length field of the Supported
 * Operating Classes element is between 2 and 253. The Current Operating Class octet indicates the
 * operating class in use for transmission and reception. The Operating Classes field lists in
 * ascending order all operating classes that the STA is capable of operating with in this country.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11SupportedOperatingClassesElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 2089786652681023988L;

  private final byte currentOperatingClass;
  private final byte[] operatingClasses;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11SupportedOperatingClassesElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11SupportedOperatingClassesElement newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11SupportedOperatingClassesElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11SupportedOperatingClassesElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.SUPPORTED_OPERATING_CLASSES);

    int infoLen = getLengthAsInt();
    if (infoLen < 1) {
      throw new IllegalRawDataException(
          "The length must be more than 0 but is actually: " + infoLen);
    }

    this.currentOperatingClass = rawData[offset + 2];
    if (infoLen == 1) {
      this.operatingClasses = new byte[0];
    } else {
      this.operatingClasses = ByteArrays.getSubArray(rawData, offset + 3, infoLen - 1);
    }
  }

  /** @param builder builder */
  private Dot11SupportedOperatingClassesElement(Builder builder) {
    super(builder);

    if (builder.operatingClasses.length > 254) {
      throw new IllegalArgumentException(
          "Too long operatingClasses: " + ByteArrays.toHexString(builder.operatingClasses, " "));
    }

    this.currentOperatingClass = builder.currentOperatingClass;
    this.operatingClasses = ByteArrays.clone(builder.operatingClasses);
  }

  /** @return currentOperatingClass */
  public byte getCurrentOperatingClass() {
    return currentOperatingClass;
  }

  /** @return currentOperatingClass */
  public int getCurrentOperatingClassAsInt() {
    return currentOperatingClass & 0xFF;
  }

  /** @return operatingClasses */
  public byte[] getOperatingClasses() {
    return ByteArrays.clone(operatingClasses);
  }

  @Override
  public int length() {
    return 3 + operatingClasses.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    rawData[2] = currentOperatingClass;
    System.arraycopy(operatingClasses, 0, rawData, 3, operatingClasses.length);
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
    result = prime * result + currentOperatingClass;
    result = prime * result + Arrays.hashCode(operatingClasses);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11SupportedOperatingClassesElement other = (Dot11SupportedOperatingClassesElement) obj;
    if (currentOperatingClass != other.currentOperatingClass) return false;
    if (!Arrays.equals(operatingClasses, other.operatingClasses)) return false;
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

    sb.append(indent).append("Supported Operating Classes:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent)
        .append("  Current Operating Class: ")
        .append(getCurrentOperatingClassAsInt())
        .append(ls);
    for (byte cls : operatingClasses) {
      sb.append(indent).append("  Operating Class: ").append(cls & 0xFF).append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private byte currentOperatingClass;
    private byte[] operatingClasses;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(
              Dot11InformationElementId.SUPPORTED_OPERATING_CLASSES.value()));
    }

    /** @param elem a Dot11SupportedOperatingClassesElement object. */
    private Builder(Dot11SupportedOperatingClassesElement elem) {
      super(elem);
      this.currentOperatingClass = elem.currentOperatingClass;
      this.operatingClasses = elem.operatingClasses;
    }

    /**
     * @param currentOperatingClass currentOperatingClass
     * @return this Builder object for method chaining.
     */
    public Builder currentOperatingClass(byte currentOperatingClass) {
      this.currentOperatingClass = currentOperatingClass;
      return this;
    }

    /**
     * @param operatingClasses operatingClasses
     * @return this Builder object for method chaining.
     */
    public Builder operatingClasses(byte[] operatingClasses) {
      this.operatingClasses = operatingClasses;
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
    public Dot11SupportedOperatingClassesElement build() {
      if (operatingClasses == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("operatingClasses: ").append(operatingClasses);
        throw new NullPointerException(sb.toString());
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) (operatingClasses.length + 1));
      }
      return new Dot11SupportedOperatingClassesElement(this);
    }
  }
}
