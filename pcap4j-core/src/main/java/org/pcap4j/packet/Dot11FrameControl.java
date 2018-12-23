/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.pcap4j.util.ByteArrays;

/**
 * Frame control field of an IEEE802.11 frame.
 *
 * <pre style="white-space: pre;">
 *      0          1          2          3          4          5          6          7
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * |       Protocol      |        Type         |                  Subtype                  |
 * |       Version       |                     |                                           |
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * |  To DS   | From DS  |More      |  Retry   |Power     |  More    |Protected |  Order   |
 * |          |          |Fragments |          |Management|  Data    |Frame     |          |
 * +----------+----------+----------+----------+----------+----------+----------+----------+
 * </pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11FrameControl implements Serializable {

  /** */
  private static final long serialVersionUID = -5402534865955179413L;

  private final ProtocolVersion protocolVersion;
  private final Dot11FrameType type;
  private final boolean toDs;
  private final boolean fromDs;
  private final boolean moreFragments;
  private final boolean retry;
  private final boolean powerManagement;
  private final boolean moreData;
  private final boolean protectedFrame;
  private final boolean order;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11FrameControl object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11FrameControl newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11FrameControl(rawData, offset, length);
  }

  private Dot11FrameControl(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a Dot11FrameControl (")
          .append(2)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    byte firstByte = rawData[offset];
    switch (firstByte & 0x03) {
      case 0:
        this.protocolVersion = ProtocolVersion.V0;
        break;
      case 1:
        this.protocolVersion = ProtocolVersion.V1;
        break;
      case 2:
        this.protocolVersion = ProtocolVersion.V2;
        break;
      case 3:
        this.protocolVersion = ProtocolVersion.V3;
        break;
      default:
        throw new AssertionError("Never get here.");
    }

    this.type =
        Dot11FrameType.getInstance((byte) (((firstByte << 2) & 0x30) | ((firstByte >> 4) & 0x0F)));
    byte secondByte = rawData[offset + 1];
    this.toDs = (secondByte & 0x01) != 0;
    this.fromDs = (secondByte & 0x02) != 0;
    this.moreFragments = (secondByte & 0x04) != 0;
    this.retry = (secondByte & 0x08) != 0;
    this.powerManagement = (secondByte & 0x10) != 0;
    this.moreData = (secondByte & 0x20) != 0;
    this.protectedFrame = (secondByte & 0x40) != 0;
    this.order = (secondByte & 0x80) != 0;
  }

  private Dot11FrameControl(Builder builder) {
    if (builder == null || builder.protocolVersion == null || builder.type == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder")
          .append(builder)
          .append(" builder.protocolVersion: ")
          .append(builder.protocolVersion)
          .append(" builder.type: ")
          .append(builder.type);
      throw new NullPointerException(sb.toString());
    }

    this.protocolVersion = builder.protocolVersion;
    this.type = builder.type;
    this.toDs = builder.toDs;
    this.fromDs = builder.fromDs;
    this.moreFragments = builder.moreFragments;
    this.retry = builder.retry;
    this.powerManagement = builder.powerManagement;
    this.moreData = builder.moreData;
    this.protectedFrame = builder.protectedFrame;
    this.order = builder.order;
  }

  /** @return protocolVersion */
  public ProtocolVersion getProtocolVersion() {
    return protocolVersion;
  }

  /** @return type */
  public Dot11FrameType getType() {
    return type;
  }

  /** @return toDs */
  public boolean isToDs() {
    return toDs;
  }

  /** @return fromDs */
  public boolean isFromDs() {
    return fromDs;
  }

  /** @return moreFragments */
  public boolean isMoreFragments() {
    return moreFragments;
  }

  /** @return retry */
  public boolean isRetry() {
    return retry;
  }

  /** @return powerManagement */
  public boolean isPowerManagement() {
    return powerManagement;
  }

  /** @return moreData */
  public boolean isMoreData() {
    return moreData;
  }

  /** @return protectedFrame */
  public boolean isProtectedFrame() {
    return protectedFrame;
  }

  /** @return order */
  public boolean isOrder() {
    return order;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[2];
    data[0] |= protocolVersion.value;
    data[0] |= type.getType().getValue() << 2;
    data[0] |= type.value() << 4;
    if (toDs) {
      data[1] |= 0x01;
    }
    if (fromDs) {
      data[1] |= 0x02;
    }
    if (moreFragments) {
      data[1] |= 0x04;
    }
    if (retry) {
      data[1] |= 0x08;
    }
    if (powerManagement) {
      data[1] |= 0x10;
    }
    if (moreData) {
      data[1] |= 0x20;
    }
    if (protectedFrame) {
      data[1] |= 0x40;
    }
    if (order) {
      data[1] |= 0x80;
    }
    return data;
  }

  /** @return length */
  public int length() {
    return 2;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return String representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("Protocol Version: ")
        .append(protocolVersion)
        .append(ls)
        .append(indent)
        .append("Type/Subtype: ")
        .append(type)
        .append(ls)
        .append(indent)
        .append("To DS: ")
        .append(toDs)
        .append(ls)
        .append(indent)
        .append("From DS: ")
        .append(fromDs)
        .append(ls)
        .append(indent)
        .append("More Fragments: ")
        .append(moreFragments)
        .append(ls)
        .append(indent)
        .append("Retry: ")
        .append(retry)
        .append(ls)
        .append(indent)
        .append("Power Management: ")
        .append(powerManagement)
        .append(ls)
        .append(indent)
        .append("More Data: ")
        .append(moreData)
        .append(ls)
        .append(indent)
        .append("Protected Frame: ")
        .append(protectedFrame)
        .append(ls)
        .append(indent)
        .append("Order: ")
        .append(order)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (fromDs ? 1231 : 1237);
    result = prime * result + (moreData ? 1231 : 1237);
    result = prime * result + (moreFragments ? 1231 : 1237);
    result = prime * result + (order ? 1231 : 1237);
    result = prime * result + (powerManagement ? 1231 : 1237);
    result = prime * result + (protectedFrame ? 1231 : 1237);
    result = prime * result + ((protocolVersion == null) ? 0 : protocolVersion.hashCode());
    result = prime * result + (retry ? 1231 : 1237);
    result = prime * result + (toDs ? 1231 : 1237);
    result = prime * result + ((type == null) ? 0 : type.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11FrameControl other = (Dot11FrameControl) obj;
    if (fromDs != other.fromDs) return false;
    if (moreData != other.moreData) return false;
    if (moreFragments != other.moreFragments) return false;
    if (order != other.order) return false;
    if (powerManagement != other.powerManagement) return false;
    if (protectedFrame != other.protectedFrame) return false;
    if (protocolVersion != other.protocolVersion) return false;
    if (retry != other.retry) return false;
    if (toDs != other.toDs) return false;
    if (!type.equals(other.type)) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder {

    private ProtocolVersion protocolVersion;
    private Dot11FrameType type;
    private boolean toDs;
    private boolean fromDs;
    private boolean moreFragments;
    private boolean retry;
    private boolean powerManagement;
    private boolean moreData;
    private boolean protectedFrame;
    private boolean order;

    /** */
    public Builder() {}

    private Builder(Dot11FrameControl obj) {
      this.protocolVersion = obj.protocolVersion;
      this.type = obj.type;
      this.toDs = obj.toDs;
      this.fromDs = obj.fromDs;
      this.moreFragments = obj.moreFragments;
      this.retry = obj.retry;
      this.powerManagement = obj.powerManagement;
      this.moreData = obj.moreData;
      this.protectedFrame = obj.protectedFrame;
      this.order = obj.order;
    }

    /**
     * @param protocolVersion protocolVersion
     * @return this Builder object for method chaining.
     */
    public Builder protocolVersion(ProtocolVersion protocolVersion) {
      this.protocolVersion = protocolVersion;
      return this;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(Dot11FrameType type) {
      this.type = type;
      return this;
    }

    /**
     * @param toDs toDs
     * @return this Builder object for method chaining.
     */
    public Builder toDs(boolean toDs) {
      this.toDs = toDs;
      return this;
    }

    /**
     * @param fromDs fromDs
     * @return this Builder object for method chaining.
     */
    public Builder fromDs(boolean fromDs) {
      this.fromDs = fromDs;
      return this;
    }

    /**
     * @param moreFragments moreFragments
     * @return this Builder object for method chaining.
     */
    public Builder moreFragments(boolean moreFragments) {
      this.moreFragments = moreFragments;
      return this;
    }

    /**
     * @param retry retry
     * @return this Builder object for method chaining.
     */
    public Builder retry(boolean retry) {
      this.retry = retry;
      return this;
    }

    /**
     * @param powerManagement powerManagement
     * @return this Builder object for method chaining.
     */
    public Builder powerManagement(boolean powerManagement) {
      this.powerManagement = powerManagement;
      return this;
    }

    /**
     * @param moreData moreData
     * @return this Builder object for method chaining.
     */
    public Builder moreData(boolean moreData) {
      this.moreData = moreData;
      return this;
    }

    /**
     * @param protectedFrame protectedFrame
     * @return this Builder object for method chaining.
     */
    public Builder protectedFrame(boolean protectedFrame) {
      this.protectedFrame = protectedFrame;
      return this;
    }

    /**
     * @param order order
     * @return this Builder object for method chaining.
     */
    public Builder order(boolean order) {
      this.order = order;
      return this;
    }

    /** @return a new Dot11FrameControl object. */
    public Dot11FrameControl build() {
      return new Dot11FrameControl(this);
    }
  }

  /**
   * Protocol version of IEEE802.11 frame
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum ProtocolVersion {

    /** v0 (00) */
    V0(0),

    /** v1 (01) */
    V1(1),

    /** v2 (10) */
    V2(2),

    /** v3 (11) */
    V3(3);

    private final int value;

    private ProtocolVersion(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
