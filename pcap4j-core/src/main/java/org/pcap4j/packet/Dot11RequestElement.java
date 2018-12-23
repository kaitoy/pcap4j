/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Request element
 *
 * <pre style="white-space: pre;">
 *       1         1              variable
 * +----------+----------+------------------------
 * |Element ID|  Length  | Requested Element IDs
 * +----------+----------+------------------------
 * Element ID: 10
 * </pre>
 *
 * The Requested Element IDs are the list of elements that are requested to be included in the Probe
 * Response frame. The Requested Element IDs are listed in order of increasing element ID.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11RequestElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = -4248529314922213901L;

  private final List<Dot11InformationElementId> requestedElementIds;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11RequestElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11RequestElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11RequestElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11RequestElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.REQUEST);
    int infoLen = getLengthAsInt();
    this.requestedElementIds = new ArrayList<Dot11InformationElementId>(infoLen);
    for (int i = 0; i < infoLen; i++) {
      requestedElementIds.add(Dot11InformationElementId.getInstance(rawData[offset + 2 + i]));
    }
  }

  /** @param builder builder */
  private Dot11RequestElement(Builder builder) {
    super(builder);

    if (builder.requestedElementIds.size() > 255) {
      throw new IllegalArgumentException(
          "Too long requestedElementIds: " + builder.requestedElementIds);
    }

    this.requestedElementIds =
        new ArrayList<Dot11InformationElementId>(builder.requestedElementIds);
  }

  /** @return requestedElementIds */
  public List<Dot11InformationElementId> getRequestedElementIds() {
    return new ArrayList<Dot11InformationElementId>(requestedElementIds);
  }

  @Override
  public int length() {
    return 2 + requestedElementIds.size();
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    int i = 0;
    for (Dot11InformationElementId id : requestedElementIds) {
      rawData[2 + i] = id.value();
      i++;
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
    result = prime * result + requestedElementIds.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11RequestElement other = (Dot11RequestElement) obj;
    if (!requestedElementIds.equals(other.requestedElementIds)) return false;
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

    sb.append(indent).append("Request:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    for (Dot11InformationElementId id : requestedElementIds) {
      sb.append(indent).append("  Requested Element: ").append(id).append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private List<Dot11InformationElementId> requestedElementIds;

    /** */
    public Builder() {
      elementId(Dot11InformationElementId.getInstance(Dot11InformationElementId.REQUEST.value()));
    }

    /** @param elem a Dot11RequestElement object. */
    private Builder(Dot11RequestElement elem) {
      super(elem);
      this.requestedElementIds = elem.requestedElementIds;
    }

    /**
     * @param requestedElementIds requestedElementIds
     * @return this Builder object for method chaining.
     */
    public Builder requestedElementIds(List<Dot11InformationElementId> requestedElementIds) {
      this.requestedElementIds = requestedElementIds;
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
    public Dot11RequestElement build() {
      if (requestedElementIds == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("requestedElementIds: ").append(requestedElementIds);
        throw new NullPointerException(sb.toString());
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) requestedElementIds.size());
      }
      return new Dot11RequestElement(this);
    }
  }
}
