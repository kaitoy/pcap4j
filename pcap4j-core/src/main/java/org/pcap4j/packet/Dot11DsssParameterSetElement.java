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
 * IEEE802.11 DSSS Parameter Set element
 *
 * <pre style="white-space: pre;">
 *       1                 1               1
 * +---------------+---------------+---------------+
 * |  Element ID   |    Length     |Current Channel|
 * +---------------+---------------+---------------+
 * Element ID: 3
 * </pre>
 *
 * The DSSS Parameter Set element contains information to allow channel number identification for
 * STAs. The Information field contains a single parameter containing the dot11CurrentChannel. The
 * length of the dot11CurrentChannel parameter is 1 octet.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11DsssParameterSetElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 3289074676325930942L;

  private final byte currentChannel;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11DsssParameterSetElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11DsssParameterSetElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11DsssParameterSetElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11DsssParameterSetElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.DSSS_PARAMETER_SET);

    if (getLengthAsInt() != 1) {
      throw new IllegalRawDataException(
          "The length must be 1 but is actually: " + getLengthAsInt());
    }

    this.currentChannel = rawData[offset + 2];
  }

  /** @param builder builder */
  private Dot11DsssParameterSetElement(Builder builder) {
    super(builder);
    this.currentChannel = builder.currentChannel;
  }

  /** @return currentChannel */
  public byte getCurrentChannel() {
    return currentChannel;
  }

  /** @return currentChannel */
  public int getCurrentChannelAsInt() {
    return currentChannel & 0xFF;
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
    rawData[2] = currentChannel;
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
    result = prime * result + currentChannel;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11DsssParameterSetElement other = (Dot11DsssParameterSetElement) obj;
    if (currentChannel != other.currentChannel) return false;
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

    sb.append(indent).append("DSSS Parameter Set:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent).append("  Current Channel: ").append(getCurrentChannelAsInt()).append(ls);

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private byte currentChannel;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(
              Dot11InformationElementId.DSSS_PARAMETER_SET.value()));
    }

    /** @param elem a Dot11DsssParameterSetElement object. */
    private Builder(Dot11DsssParameterSetElement elem) {
      super(elem);
      this.currentChannel = elem.currentChannel;
    }

    /**
     * @param currentChannel currentChannel
     * @return this Builder object for method chaining.
     */
    public Builder currentChannel(byte currentChannel) {
      this.currentChannel = currentChannel;
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
    public Dot11DsssParameterSetElement build() {
      if (getCorrectLengthAtBuild()) {
        length((byte) 1);
      }
      return new Dot11DsssParameterSetElement(this);
    }
  }
}
