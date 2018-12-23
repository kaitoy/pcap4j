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
 * IEEE802.11 SSID List element
 *
 * <pre style="white-space: pre;">
 *       1         1          variable
 * +----------+----------+-------------
 * |Element ID|  Length  | SSID List
 * +----------+----------+-------------
 * Element ID: 84
 * </pre>
 *
 * The SSID List field is a list of SSID elements, each including the element ID, length field and
 * SSID information field for which the STA is requesting information.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11SsidListElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 1424839847229135121L;

  private final List<Dot11SsidElement> ssidList;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11SsidListElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11SsidListElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11SsidListElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11SsidListElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.SSID_LIST);

    int infoLen = getLengthAsInt();
    this.ssidList = new ArrayList<Dot11SsidElement>();
    for (int i = offset + 2; infoLen > 0; ) {
      Dot11SsidElement ssid = Dot11SsidElement.newInstance(rawData, i, infoLen);
      ssidList.add(ssid);
      int ssidLen = ssid.length();
      infoLen -= ssidLen;
      i += ssidLen;
    }
  }

  /** @param builder builder */
  private Dot11SsidListElement(Builder builder) {
    super(builder);
    this.ssidList = new ArrayList<Dot11SsidElement>(builder.ssidList);
  }

  /** @return ssidList */
  public List<Dot11SsidElement> getSsidList() {
    return new ArrayList<Dot11SsidElement>(ssidList);
  }

  @Override
  public int length() {
    int len = 2;
    for (Dot11SsidElement ssid : ssidList) {
      len += ssid.length();
    }
    return len;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    int offset = 2;
    for (Dot11SsidElement ssid : ssidList) {
      byte[] rawSsid = ssid.getRawData();
      System.arraycopy(rawSsid, 0, rawData, offset, rawSsid.length);
      offset += rawSsid.length;
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
    result = prime * result + ssidList.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11SsidListElement other = (Dot11SsidListElement) obj;
    if (!ssidList.equals(other.ssidList)) return false;
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

    sb.append(indent).append("SSID List:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    for (Dot11SsidElement ssid : ssidList) {
      sb.append(indent).append("  SSID: ").append(ssid.getSsid()).append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private List<Dot11SsidElement> ssidList;

    /** */
    public Builder() {
      elementId(Dot11InformationElementId.getInstance(Dot11InformationElementId.SSID_LIST.value()));
    }

    /** @param elem a Dot11SsidListElement object. */
    private Builder(Dot11SsidListElement elem) {
      super(elem);
      this.ssidList = elem.ssidList;
    }

    /**
     * @param ssidList ssidList
     * @return this Builder object for method chaining.
     */
    public Builder ssidList(List<Dot11SsidElement> ssidList) {
      this.ssidList = ssidList;
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
    public Dot11SsidListElement build() {
      if (ssidList == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("ssidList: ").append(ssidList);
        throw new NullPointerException(sb.toString());
      }

      int len = 0;
      for (Dot11SsidElement ssid : ssidList) {
        len += ssid.length();
      }
      if (len > 255) {
        throw new IllegalArgumentException("Too long ssidList: " + ssidList);
      }

      if (getCorrectLengthAtBuild()) {
        length((byte) len);
      }
      return new Dot11SsidListElement(this);
    }
  }
}
