/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.namednumber.Dot11AccessNetworkType;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.packet.namednumber.Dot11VenueInfo;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Interworking element
 *
 * <pre style="white-space: pre;">
 *        1              1              1            0 or 2         0 or 6
 * +--------------+--------------+--------------+--------------+--------------+
 * |  Element ID  |   Length     |Access Network|  Venue Info  |    HESSID    |
 * |              |              |Options       |  (optional)  |  (optional)  |
 * +--------------+--------------+--------------+--------------+--------------+
 * Element ID: 107
 *
 * Access Network Options field:
 *     B0       B1       B2       B3       B4       B5       B6       B7
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * |        Access Network Type        |Internet|  ASRA  |  ESR   |  UESA  |
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * </pre>
 *
 * The Interworking element contains information about the interworking service capabilities of a
 * STA.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11InterworkingElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = -5151120333283703306L;

  private final Dot11AccessNetworkType accessnetworkType;
  private final boolean internet;
  private final boolean asra;
  private final boolean esr;
  private final boolean uesa;
  private final Dot11VenueInfo venueInfo;
  private final byte[] hessid;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11InterworkingElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11InterworkingElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11InterworkingElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11InterworkingElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.INTERWORKING);

    int infoLen = getLengthAsInt();
    if (infoLen != 1 && infoLen != 3 && infoLen != 7 && infoLen != 9) {
      throw new IllegalRawDataException(
          "The length must be 1 or 3 or 7 or 9 but is actually: " + infoLen);
    }

    this.accessnetworkType =
        Dot11AccessNetworkType.getInstance((byte) (rawData[offset + 2] & 0x0F));
    this.internet = (rawData[offset + 2] & 0x10) != 0;
    this.asra = (rawData[offset + 2] & 0x20) != 0;
    this.esr = (rawData[offset + 2] & 0x40) != 0;
    this.uesa = (rawData[offset + 2] & 0x80) != 0;
    if (infoLen == 3 || infoLen == 9) {
      this.venueInfo = Dot11VenueInfo.getInstance(ByteArrays.getShort(rawData, offset + 3));
    } else {
      this.venueInfo = null;
    }
    if (infoLen == 7) {
      this.hessid = ByteArrays.getSubArray(rawData, offset + 3, 6);
    } else if (infoLen == 9) {
      this.hessid = ByteArrays.getSubArray(rawData, offset + 5, 6);
    } else {
      this.hessid = null;
    }
  }

  /** @param builder builder */
  private Dot11InterworkingElement(Builder builder) {
    super(builder);
    if (builder.accessnetworkType == null) {
      throw new NullPointerException("builder.accessnetworkType is null.");
    }
    if (builder.hessid.length != 6) {
      throw new IllegalArgumentException(
          "builder.hessid.length must be 6. builder.hessid.length: "
              + ByteArrays.toHexString(builder.hessid, " "));
    }

    this.accessnetworkType = builder.accessnetworkType;
    this.internet = builder.internet;
    this.asra = builder.asra;
    this.esr = builder.esr;
    this.uesa = builder.uesa;
    this.venueInfo = builder.venueInfo;
    this.hessid = builder.hessid;
  }

  /** @return accessnetworkType */
  public Dot11AccessNetworkType getAccessnetworkType() {
    return accessnetworkType;
  }

  /** @return true if the internet field is set to 1; false otherwise. */
  public boolean isInternetAccessible() {
    return internet;
  }

  /** @return true if the ASRA field is set to 1; false otherwise. */
  public boolean isAsra() {
    return asra;
  }

  /** @return true if the ESR field is set to 1; false otherwise. */
  public boolean isEsr() {
    return esr;
  }

  /** @return true if the UESA field is set to 1; false otherwise. */
  public boolean isUesa() {
    return uesa;
  }

  /** @return venueInfo. May be null. */
  public Dot11VenueInfo getVenueInfo() {
    return venueInfo;
  }

  /** @return hessid. May be null. */
  public byte[] getHessid() {
    if (hessid == null) {
      return null;
    } else {
      return ByteArrays.clone(hessid);
    }
  }

  @Override
  public int length() {
    int len = 3;
    if (venueInfo != null) {
      len += 2;
    }
    if (hessid != null) {
      len += 6;
    }
    return len;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];

    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    rawData[2] = accessnetworkType.value();
    if (internet) {
      rawData[2] |= 0x10;
    }
    if (asra) {
      rawData[2] |= 0x20;
    }
    if (esr) {
      rawData[2] |= 0x40;
    }
    if (uesa) {
      rawData[2] |= 0x80;
    }

    int offset = 3;
    if (venueInfo != null) {
      System.arraycopy(ByteArrays.toByteArray(venueInfo.value()), 0, rawData, offset, 2);
      offset += 2;
    }
    if (hessid != null) {
      System.arraycopy(hessid, 0, rawData, offset, 6);
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
    result = prime * result + accessnetworkType.hashCode();
    result = prime * result + (asra ? 1231 : 1237);
    result = prime * result + (esr ? 1231 : 1237);
    result = prime * result + Arrays.hashCode(hessid);
    result = prime * result + (internet ? 1231 : 1237);
    result = prime * result + (uesa ? 1231 : 1237);
    result = prime * result + ((venueInfo == null) ? 0 : venueInfo.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!super.equals(obj)) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11InterworkingElement other = (Dot11InterworkingElement) obj;
    if (!accessnetworkType.equals(other.accessnetworkType)) return false;
    if (asra != other.asra) return false;
    if (esr != other.esr) return false;
    if (!Arrays.equals(hessid, other.hessid)) return false;
    if (internet != other.internet) return false;
    if (uesa != other.uesa) return false;
    if (venueInfo == null) {
      if (other.venueInfo != null) return false;
    } else if (!venueInfo.equals(other.venueInfo)) return false;
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

    sb.append(indent).append("Interworking:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent).append("  Access Network Type: ").append(accessnetworkType).append(ls);
    sb.append(indent).append("  Internet Accessible: ").append(internet).append(ls);
    sb.append(indent).append("  ASRA: ").append(asra).append(ls);
    sb.append(indent).append("  ESR: ").append(esr).append(ls);
    sb.append(indent).append("  UESA: ").append(uesa).append(ls);
    if (venueInfo != null) {
      sb.append(indent).append("  Venue Info: ").append(venueInfo).append(ls);
    }
    if (hessid != null) {
      sb.append(indent)
          .append("  HESSID: 0x")
          .append(ByteArrays.toHexString(hessid, ""))
          .append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private Dot11AccessNetworkType accessnetworkType;
    private boolean internet;
    private boolean asra;
    private boolean esr;
    private boolean uesa;
    private Dot11VenueInfo venueInfo;
    private byte[] hessid;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(Dot11InformationElementId.INTERWORKING.value()));
    }

    /** @param obj a Dot11InterworkingElement object. */
    private Builder(Dot11InterworkingElement obj) {
      super(obj);
      this.accessnetworkType = obj.accessnetworkType;
      this.internet = obj.internet;
      this.asra = obj.asra;
      this.esr = obj.esr;
      this.uesa = obj.uesa;
      this.venueInfo = obj.venueInfo;
      this.hessid = obj.hessid;
    }

    /**
     * @param accessnetworkType accessnetworkType
     * @return this Builder object for method chaining.
     */
    public Builder accessnetworkType(Dot11AccessNetworkType accessnetworkType) {
      this.accessnetworkType = accessnetworkType;
      return this;
    }

    /**
     * @param internet internet
     * @return this Builder object for method chaining.
     */
    public Builder internet(boolean internet) {
      this.internet = internet;
      return this;
    }

    /**
     * @param asra asra
     * @return this Builder object for method chaining.
     */
    public Builder asra(boolean asra) {
      this.asra = asra;
      return this;
    }

    /**
     * @param esr esr
     * @return this Builder object for method chaining.
     */
    public Builder esr(boolean esr) {
      this.esr = esr;
      return this;
    }

    /**
     * @param uesa uesa
     * @return this Builder object for method chaining.
     */
    public Builder uesa(boolean uesa) {
      this.uesa = uesa;
      return this;
    }

    /**
     * @param venueInfo venueInfo
     * @return this Builder object for method chaining.
     */
    public Builder venueInfo(Dot11VenueInfo venueInfo) {
      this.venueInfo = venueInfo;
      return this;
    }

    /**
     * @param hessid hessid
     * @return this Builder object for method chaining.
     */
    public Builder hessid(byte[] hessid) {
      this.hessid = hessid;
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
    public Dot11InterworkingElement build() {
      if (getCorrectLengthAtBuild()) {
        int len = 1;
        if (venueInfo != null) {
          len += 2;
        }
        if (hessid != null) {
          len += 6;
        }
        length((byte) len);
      }
      return new Dot11InterworkingElement(this);
    }
  }
}
