/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import java.io.Serializable;
import java.util.Arrays;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.factory.ClassifiedDataFactories;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4InternetTimestampOption implements IpV4Option {

  /**
   *
   */
  private static final long serialVersionUID = -7218329498227977405L;

  /*
   *  +--------+--------+--------+--------+
   *  |01000100| length | pointer|oflw|flg|
   *  +--------+--------+--------+--------+
   *  |         internet address          |
   *  +--------+--------+--------+--------+
   *  |             timestamp             |
   *  +--------+--------+--------+--------+
   *  |                 .                 |
   *                    .
   *                    .
   *    Type=68
   */

  private final IpV4OptionType type = IpV4OptionType.INTERNET_TIMESTAMP;
  private final byte length;
  private final byte pointer;
  private final byte overflow;
  private final IpV4InternetTimestampOptionFlag flag;
  private final IpV4InternetTimestampOptionData data;

  public static IpV4InternetTimestampOption newInstance(byte[] rawData) {
    return new IpV4InternetTimestampOption(rawData);
  }

  private IpV4InternetTimestampOption(byte[] rawData) {
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

    this.length = rawData[1];

    if (rawData.length < length) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
        .append(length)
        .append("). data: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (length % INT_SIZE_IN_BYTES != 0) {
      throw new IllegalRawDataException(
                  "Invalid length for this option: " + length
                );
    }

    this.pointer = rawData[2];
    this.overflow = (byte)((rawData[3] & 0xF0) >> 4);
    this.flag
      = IpV4InternetTimestampOptionFlag.getInstance((byte)(rawData[3] & 0x0F));
    this.data
      = ClassifiedDataFactories
          .getFactory(
             IpV4InternetTimestampOptionData.class,
             IpV4InternetTimestampOptionFlag.class
           ).newData(
               ByteArrays.getSubArray(rawData, 4, length),
               flag
             );
  }

  private IpV4InternetTimestampOption(Builder builder) {
    if (
        builder == null
     || builder.flag == null
     || builder.data == null
   ) {
     StringBuilder sb = new StringBuilder();
     sb.append("builder: ").append(builder)
       .append(" builder.flag: ").append(builder.flag)
       .append(" builder.data: ").append(builder.data);
     throw new NullPointerException(sb.toString());
   }

    this.pointer = builder.pointer;
    this.overflow = builder.overflow;
    this.flag = builder.flag;
    this.data = builder.data;

    if (builder.correctLengthAtBuild) {
      this.length = (byte)length();
    }
    else {
      this.length = builder.length;
    }
  }

  public IpV4OptionType getType() { return type; }

  /**
   *
   * @return
   */
  public byte getLength() { return length; }

  /**
   *
   * @return
   */
  public int getLengthAsInt() { return 0xFF & length; }

  /**
   *
   * @return
   */
  public byte getPointer() { return pointer; }

  /**
   *
   * @return
   */
  public int getPointerAsInt() { return 0xFF & pointer; }

  /**
   *
   * @return
   */
  public byte getOverflow() { return overflow; }

  /**
   *
   * @return
   */
  public int getOverflowAsInt() { return 0xFF & overflow; }

  /**
   *
   * @return
   */
  public IpV4InternetTimestampOptionFlag getFlag() { return flag; }

  /**
   *
   * @return
   */
  public IpV4InternetTimestampOptionData getData() { return data; }

  public int length() { return 4 + data.length(); }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getType().value();
    rawData[1] = length;
    rawData[2] = pointer;
    rawData[3] = flag.value();
    rawData[3] = (byte)(rawData[3] | (overflow << 4));
    System.arraycopy(data.getRawData(), 0, rawData, 4, data.length());
    return rawData;
  }

  /**
   *
   * @return
   */
  public Builder getBuilder() { return new Builder(this); }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[option-type: ")
      .append(getType());
    sb.append("] [option-length: ")
      .append(getLengthAsInt());
    sb.append(" bytes] [pointer: ")
      .append(getPointerAsInt());
    sb.append("] [overflow: ")
      .append(getOverflowAsInt());
    sb.append("] [flag: ")
      .append(flag);
    sb.append("] [data:")
      .append(data);
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
  implements LengthBuilder<IpV4InternetTimestampOption> {

    private byte length;
    private byte pointer;
    private byte overflow;
    private IpV4InternetTimestampOptionFlag flag;
    private IpV4InternetTimestampOptionData data;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(IpV4InternetTimestampOption option) {
      this.length = option.length;
      this.pointer = option.pointer;
      this.overflow = option.overflow;
      this.flag = option.flag;
      this.data = option.data;
    }

    /**
     *
     * @param length
     * @return
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     *
     * @param pointer
     * @return
     */
    public Builder pointer(byte pointer) {
      this.pointer = pointer;
      return this;
    }

    /**
     *
     * @param overflow
     * @return
     */
    public Builder overflow(byte overflow) {
      this.overflow = overflow;
      return this;
    }

    /**
     *
     * @param flag
     * @return
     */
    public Builder flag(IpV4InternetTimestampOptionFlag flag) {
      this.flag = flag;
      return this;
    }

    /**
     *
     * @param data
     * @return
     */
    public Builder data(IpV4InternetTimestampOptionData data) {
      this.data = data;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    public IpV4InternetTimestampOption build() {
      return new IpV4InternetTimestampOption(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static interface IpV4InternetTimestampOptionData extends Serializable {

    // /* must implement if use DynamicIpV4InternetTimestampDataFactory */
    // public static IpV4InternetTimestampData newInstance(byte[] rawData);

    /**
     *
     * @return
     */
    public int length();

    /**
     *
     * @return
     */
    public byte[] getRawData();

  }


}
