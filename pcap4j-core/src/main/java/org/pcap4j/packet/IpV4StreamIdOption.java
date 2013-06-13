/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4StreamIdOption implements IpV4Option {

  /*
   *  +--------+--------+--------+--------+
   *  |10001000|00000100|    Stream ID    |
   *  +--------+--------+--------+--------+
   *   Type=136 Length=4
   */

  /**
   *
   */
  private static final long serialVersionUID = -2067863811913941432L;

  private final IpV4OptionType type = IpV4OptionType.STREAM_ID;
  private final byte length;
  private final short streamId;

  /**
   *
   * @param rawData
   * @return a new IpV4StreamIdOption object.
   */
  public static IpV4StreamIdOption newInstance(byte[] rawData) {
    return new IpV4StreamIdOption(rawData);
  }

  private IpV4StreamIdOption(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0] != getType().value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
        .append(getType().valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[1] != 4) {
      throw new IllegalRawDataException(
                  "Invalid value of length field: " + rawData[1]
                );
    }

    this.length = rawData[1];
    this.streamId = ByteArrays.getShort(rawData, 2);
  }

  private IpV4StreamIdOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.streamId = builder.streamId;

    if (builder.correctLengthAtBuild) {
      this.length = (byte)length();
    }
    else {
      this.length = builder.length;
    }
  }

  public IpV4OptionType getType() {
    return type;
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
   * @return streamId
   */
  public short getStreamId() { return streamId; }

  /**
   *
   * @return streamId
   */
  public int getStreamIdAsInt() { return 0xFFFF & streamId; }

  public int length() { return 4; }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getType().value();
    rawData[1] = length;
    rawData[2] = (byte)(streamId >> 8);
    rawData[3] = (byte)streamId;
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
    sb.append("[option-type: ")
      .append(getType());
    sb.append("] [option-length: ")
      .append(getLengthAsInt());
    sb.append(" bytes] [streamId: ")
      .append(getStreamIdAsInt());
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
   * @since pcap4j 0.9.11
   */
  public static final class Builder
  implements LengthBuilder<IpV4StreamIdOption> {

    private byte length;
    private short streamId;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(IpV4StreamIdOption option) {
      this.length = option.length;
      this.streamId = option.streamId;
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
     * @param streamId
     * @return this Builder object for method chaining.
     */
    public Builder streamId(short streamId) {
      this.streamId = streamId;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    public IpV4StreamIdOption build() {
      return new IpV4StreamIdOption(this);
    }

  }

}
