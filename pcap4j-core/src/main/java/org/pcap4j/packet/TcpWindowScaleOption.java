/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.0
 */
public final class TcpWindowScaleOption implements TcpOption {

  /*
   * http://tools.ietf.org/html/draft-ietf-tcpm-1323bis-21
   *
   *   +---------+---------+---------+
   *   | Kind=3  |Length=3 |shift.cnt|
   *   +---------+---------+---------+
   *        1         1         1
   */

  /**
   *
   */
  private static final long serialVersionUID = -1755743386204601523L;

  private final TcpOptionKind kind = TcpOptionKind.WINDOW_SCALE;
  private final byte length;
  private final byte shiftCount;

  /**
   *
   * @param rawData
   * @return a new TcpWindowScaleOption object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static TcpWindowScaleOption newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new TcpWindowScaleOption(rawData);
  }

  private TcpWindowScaleOption(byte[] rawData) throws IllegalRawDataException {
    if (rawData.length < 3) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 2. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0] != kind.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The kind must be: ")
        .append(kind.valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[1] != 3) {
      throw new IllegalRawDataException(
                  "The value of length field must be 3 but: " + rawData[1]
                );
    }

    this.length = rawData[1];
    this.shiftCount = rawData[2];
  }

  private TcpWindowScaleOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.shiftCount = builder.shiftCount;

    if (builder.correctLengthAtBuild) {
      this.length = (byte)length();
    }
    else {
      this.length = builder.length;
    }
  }

  @Override
  public TcpOptionKind getKind() {
    return kind;
  }

  /**
   *
   * @return length
   */
  public byte getLength() { return length; }

  /**
   *
   * @return length
   */
  public int getLengthAsInt() { return 0xFF & length; }

  /**
   *
   * @return shiftCount
   */
  public byte getShiftCount() { return shiftCount; }

  /**
   *
   * @return shiftCount
   */
  public int getShiftCountAsInt() { return 0xFF & shiftCount; }

  @Override
  public int length() { return 3; }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    rawData[2] = shiftCount;
    return rawData;
  }

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ")
      .append(kind);
    sb.append("] [Length: ")
      .append(getLengthAsInt());
    sb.append(" bytes] [Shift Count: ")
      .append(getShiftCountAsInt());
    sb.append("]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    return Arrays.equals((getClass().cast(obj)).getRawData(), getRawData());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.2.0
   */
  public static final class Builder
  implements LengthBuilder<TcpWindowScaleOption> {

    private byte length;
    private byte shiftCount;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(TcpWindowScaleOption option) {
      this.length = option.length;
      this.shiftCount = option.shiftCount;
    }

    /**
     *
     * @param length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     *
     * @param shiftCount
     * @return this Builder object for method chaining.
     */
    public Builder shiftCount(byte shiftCount) {
      this.shiftCount = shiftCount;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public TcpWindowScaleOption build() {
      return new TcpWindowScaleOption(this);
    }

  }

}
