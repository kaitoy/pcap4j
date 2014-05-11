/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class UnknownIpV6Option implements IpV6Option {


  /**
   *
   */
  private static final long serialVersionUID = -2090004757469984967L;

  private final IpV6OptionType type;
  private final byte dataLen;
  private final byte[] data;

  /**
   *
   * @param rawData
   * @return a new UnknownIpV6Option object.
   * @throws IllegalRawDataException
   */
  public static UnknownIpV6Option newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    return new UnknownIpV6Option(rawData);
  }

  private UnknownIpV6Option(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length < 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 1. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.type = IpV6OptionType.getInstance(rawData[0]);
    this.dataLen = rawData[1];
    this.data = ByteArrays.getSubArray(rawData, 2, dataLen);
  }

  private UnknownIpV6Option(Builder builder) {
    if (
         builder == null
      || builder.type == null
      || builder.data == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.type: ").append(builder.type)
        .append(" builder.data: ").append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.type = builder.type;
    this.data = new byte[builder.data.length];
    System.arraycopy(
      builder.data, 0, this.data, 0, builder.data.length
    );

    if (builder.correctLengthAtBuild) {
      this.dataLen = (byte)data.length;
    }
    else {
      this.dataLen = builder.dataLen;
    }
  }

  public IpV6OptionType getType() { return type; }

  /**
   *
   * @return dataLen
   */
  public byte getDataLen() { return dataLen; }

  /**
   *
   * @return dataLen
   */
  public int getDataLenAsInt() { return 0xFF & dataLen; }

  /**
   *
   * @return data
   */
  public byte[] getData() {
    byte[] copy = new byte[data.length];
    System.arraycopy(data, 0, copy, 0, data.length);
    return copy;
  }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = type.value();
    rawData[1] = dataLen;
    System.arraycopy(data, 0, rawData, 2, data.length);
    return rawData;
  }

  public int length() { return data.length + 2; }

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Option Type: ")
      .append(type)
      .append("] [Option Data Len: ")
      .append(getDataLenAsInt())
      .append(" bytes] [Option Data: 0x")
      .append(ByteArrays.toHexString(data, ""))
      .append("]");
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
  public static final class
  Builder implements LengthBuilder<UnknownIpV6Option> {

    private IpV6OptionType type;
    private byte dataLen;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(UnknownIpV6Option option) {
      this.type = option.type;
      this.dataLen = option.dataLen;
      this.data = option.data;
    }

    /**
     *
     * @param type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV6OptionType type) {
      this.type = type;
      return this;
    }

    /**
     *
     * @param dataLen
     * @return this Builder object for method chaining.
     */
    public Builder dataLen(byte dataLen) {
      this.dataLen = dataLen;
      return this;
    }

    /**
     *
     * @param data
     * @return this Builder object for method chaining.
     */
    public Builder data(byte[] data) {
      this.data = data;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    public UnknownIpV6Option build() {
      return new UnknownIpV6Option(this);
    }

  }

}
