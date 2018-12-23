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
 * IEEE802.11 Mesh ID element
 *
 * <pre style="white-space: pre;">
 *       1         1        0-32
 * +----------+----------+----------
 * |Element ID|  Length  | Mesh ID
 * +----------+----------+----------
 * Element ID: 114
 * </pre>
 *
 * The Mesh ID element is used to advertise the identification of an MBSS. The Mesh ID element is
 * transmitted in Mesh Peering Open frames, Mesh Peering Confirm frames, Mesh Peering Close frames,
 * Beacon frames, and Probe Request and Response frames. A Mesh ID field of length 0 indicates the
 * wildcard Mesh ID, which is used within Probe Request frame.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11MeshIdElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 8808363321385383483L;

  private final byte[] meshId;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11MeshIdElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11MeshIdElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11MeshIdElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11MeshIdElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.MESH_ID);

    int infoLen = getLengthAsInt();
    if (infoLen == 0) {
      this.meshId = new byte[0];
    } else {
      this.meshId = ByteArrays.getSubArray(rawData, offset + 2, infoLen);
    }
  }

  /** @param builder builder */
  private Dot11MeshIdElement(Builder builder) {
    super(builder);

    if (builder.meshId.length > 255) {
      throw new IllegalArgumentException("Too long meshId: " + builder.meshId);
    }

    this.meshId = ByteArrays.clone(builder.meshId);
  }

  /** @return meshId */
  public byte[] getMeshId() {
    return ByteArrays.clone(meshId);
  }

  @Override
  public int length() {
    return 2 + meshId.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    System.arraycopy(meshId, 0, rawData, 2, meshId.length);
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
    result = prime * result + Arrays.hashCode(meshId);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11MeshIdElement other = (Dot11MeshIdElement) obj;
    if (!Arrays.equals(meshId, other.meshId)) return false;
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

    sb.append(indent).append("Mesh ID:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent)
        .append("  Mesh ID: ")
        .append(new String(meshId))
        .append(" (0x")
        .append(ByteArrays.toHexString(meshId, ""))
        .append(")")
        .append(ls);

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private byte[] meshId;

    /** */
    public Builder() {
      elementId(Dot11InformationElementId.getInstance(Dot11InformationElementId.MESH_ID.value()));
    }

    /** @param elem a Dot11MeshIdElement object. */
    private Builder(Dot11MeshIdElement elem) {
      super(elem);
      this.meshId = elem.meshId;
    }

    /**
     * @param meshId meshId
     * @return this Builder object for method chaining.
     */
    public Builder meshId(byte[] meshId) {
      this.meshId = meshId;
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
    public Dot11MeshIdElement build() {
      if (meshId == null) {
        throw new NullPointerException("meshId is null.");
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) meshId.length);
      }
      return new Dot11MeshIdElement(this);
    }
  }
}
