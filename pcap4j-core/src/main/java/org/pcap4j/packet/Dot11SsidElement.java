/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.nio.charset.Charset;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 SSID element
 *
 * <pre style="white-space: pre;">
 *       1         1          0-32
 * +----------+----------+-------------
 * |Element ID|  Length  |    SSID
 * +----------+----------+-------------
 * Element ID: 0
 * </pre>
 *
 * A SSID field of length 0 is used within Probe Request management frames to indicate the wildcard
 * SSID. The wildcard SSID is also used in Beacon and Probe Response frames transmitted by mesh
 * STAs. When the UTF-8 SSID subfield of the Extended Capabilities element is equal to 1 in the
 * frame that includes the SSID element, the SSID is interpreted using UTF-8 encoding.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11SsidElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 2213115521616826185L;

  private static final Charset ENCODING;
  private final String ssid;

  static {
    ENCODING = Charset.forName("UTF-8");
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11SsidElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11SsidElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11SsidElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11SsidElement(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.SSID);
    this.ssid = new String(rawData, offset + 2, getLengthAsInt(), ENCODING);
  }

  /** @param builder builder */
  private Dot11SsidElement(Builder builder) {
    super(builder);

    if (builder.ssid.getBytes(ENCODING).length > 255) {
      throw new IllegalArgumentException("Too long ssid: " + builder.ssid);
    }

    this.ssid = builder.ssid;
  }

  /** @return ssid */
  public String getSsid() {
    return ssid;
  }

  @Override
  public int length() {
    return 2 + ssid.getBytes(ENCODING).length;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawSsid = ssid.getBytes(ENCODING);
    byte[] rawData = new byte[2 + rawSsid.length];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    System.arraycopy(rawSsid, 0, rawData, 2, rawSsid.length);
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
    result = prime * result + ssid.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11SsidElement other = (Dot11SsidElement) obj;
    if (!ssid.equals(other.ssid)) return false;
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

    sb.append(indent).append("SSID:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent).append("  SSID: ").append(ssid).append(ls);

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private String ssid;

    /** */
    public Builder() {
      elementId(Dot11InformationElementId.getInstance(Dot11InformationElementId.SSID.value()));
    }

    /** @param elem a Dot11SsidElement object. */
    private Builder(Dot11SsidElement elem) {
      super(elem);
      this.ssid = elem.ssid;
    }

    /**
     * @param ssid ssid
     * @return this Builder object for method chaining.
     */
    public Builder ssid(String ssid) {
      this.ssid = ssid;
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
    public Dot11SsidElement build() {
      if (ssid == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("ssid: ").append(ssid);
        throw new NullPointerException(sb.toString());
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) ssid.getBytes(ENCODING).length);
      }
      return new Dot11SsidElement(this);
    }
  }
}
