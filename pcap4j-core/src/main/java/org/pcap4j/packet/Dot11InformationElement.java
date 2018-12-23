/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Information element
 *
 * <pre style="white-space: pre;">
 *       1         1        variable
 * +----------+----------+-------------
 * |Element ID|  Length  | information
 * +----------+----------+-------------
 * </pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public abstract class Dot11InformationElement implements Serializable {

  /** */
  private static final long serialVersionUID = 3620485938137514351L;

  private final Dot11InformationElementId elementId;
  private final byte length;

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param id element ID
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  protected Dot11InformationElement(
      byte[] rawData, int offset, int length, Dot11InformationElementId id)
      throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 1. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[offset] != id.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The element ID must be ")
          .append(id.valueAsString())
          .append(" but is actually ")
          .append(rawData[offset])
          .append(". rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.elementId = id;
    this.length = rawData[1 + offset];
    int lenAsInt = getLengthAsInt();
    if (lenAsInt > length - 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData is too short. length field: ")
          .append(lenAsInt)
          .append(", rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
  }

  /** @param builder builder */
  protected Dot11InformationElement(Builder builder) {
    if (builder == null || builder.elementId == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.elementId: ")
          .append(builder.elementId);
      throw new NullPointerException(sb.toString());
    }

    this.elementId = builder.elementId;
    this.length = builder.length;
  }

  /** @return the element ID */
  public Dot11InformationElementId getElementId() {
    return elementId;
  }

  /** @return the value of the length field. */
  public byte getLength() {
    return length;
  }

  /** @return the value of the length field. */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return the length */
  public abstract int length();

  /** @return the raw data. */
  public abstract byte[] getRawData();

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + elementId.hashCode();
    result = prime * result + length;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11InformationElement other = (Dot11InformationElement) obj;
    if (!elementId.equals(other.elementId)) return false;
    if (length != other.length) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public abstract static class Builder implements LengthBuilder<Dot11InformationElement> {

    private Dot11InformationElementId elementId;
    private byte length;
    private boolean correctLengthAtBuild;

    /** */
    protected Builder() {}

    /** @param elem a Dot11InformationElement object. */
    protected Builder(Dot11InformationElement elem) {
      this.elementId = elem.elementId;
      this.length = elem.length;
    }

    /**
     * @param elementId elementId
     * @return this Builder object for method chaining.
     */
    protected Builder elementId(Dot11InformationElementId elementId) {
      this.elementId = elementId;
      return this;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    /** @return correctLengthAtBuild */
    protected boolean getCorrectLengthAtBuild() {
      return correctLengthAtBuild;
    }
  }
}
