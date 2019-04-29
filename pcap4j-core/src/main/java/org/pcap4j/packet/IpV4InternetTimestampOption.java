/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

import java.io.Serializable;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4InternetTimestampOption implements IpV4Option {

  /** */
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

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4InternetTimestampOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4InternetTimestampOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4InternetTimestampOption(rawData, offset, length);
  }

  private IpV4InternetTimestampOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[offset] != getType().value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
          .append(getType().valueAsString())
          .append(" rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = rawData[1 + offset];
    int lengthFieldAsInt = getLengthAsInt();
    if (length < lengthFieldAsInt) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
          .append(getLengthAsInt())
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (lengthFieldAsInt < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The length field value must be equal or more than 4 but it is: ")
          .append(lengthFieldAsInt);
      throw new IllegalRawDataException(sb.toString());
    }
    if (lengthFieldAsInt % INT_SIZE_IN_BYTES != 0) {
      throw new IllegalRawDataException("Invalid length for this option: " + lengthFieldAsInt);
    }

    this.pointer = rawData[2 + offset];
    this.overflow = (byte) ((rawData[3 + offset] & 0xF0) >> 4);
    this.flag = IpV4InternetTimestampOptionFlag.getInstance((byte) (rawData[3 + offset] & 0x0F));
    if (lengthFieldAsInt > 4) {
      this.data =
          PacketFactories.getFactory(
                  IpV4InternetTimestampOptionData.class, IpV4InternetTimestampOptionFlag.class)
              .newInstance(rawData, 4 + offset, lengthFieldAsInt - 4, flag);
    } else {
      this.data = null;
    }
  }

  private IpV4InternetTimestampOption(Builder builder) {
    if (builder == null || builder.flag == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.flag: ").append(builder.flag);
      throw new NullPointerException(sb.toString());
    }

    this.pointer = builder.pointer;
    this.overflow = builder.overflow;
    this.flag = builder.flag;
    this.data = builder.data;

    if (builder.correctLengthAtBuild) {
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public IpV4OptionType getType() {
    return type;
  }

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return pointer */
  public byte getPointer() {
    return pointer;
  }

  /** @return pointer */
  public int getPointerAsInt() {
    return 0xFF & pointer;
  }

  /** @return overflow */
  public byte getOverflow() {
    return overflow;
  }

  /** @return overflow */
  public int getOverflowAsInt() {
    return 0xFF & overflow;
  }

  /** @return flag */
  public IpV4InternetTimestampOptionFlag getFlag() {
    return flag;
  }

  /** @return data, which may be null. */
  public IpV4InternetTimestampOptionData getData() {
    return data;
  }

  @Override
  public int length() {
    return 4 + (data != null ? data.length() : 0);
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getType().value();
    rawData[1] = length;
    rawData[2] = pointer;
    rawData[3] = flag.value();
    rawData[3] = (byte) (rawData[3] | (overflow << 4));
    if (data != null) {
      System.arraycopy(data.getRawData(), 0, rawData, 4, data.length());
    }
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[option-type: ").append(getType());
    sb.append("] [option-length: ").append(getLengthAsInt());
    sb.append(" bytes] [pointer: ").append(getPointerAsInt());
    sb.append("] [overflow: ").append(getOverflowAsInt());
    sb.append("] [flag: ").append(flag).append("]");
    if (data != null) {
      sb.append(" [data: ").append(data).append("]");
    }
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    IpV4InternetTimestampOption other = (IpV4InternetTimestampOption) obj;
    if (length == other.length
        && pointer == other.pointer
        && overflow == other.overflow
        && flag.equals(other.flag)) {
      if (data == null) {
        return other.data == null;
      } else {
        return data.equals(other.data);
      }
    } else {
      return false;
    }
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + pointer;
    result = 31 * result + overflow;
    result = 31 * result + flag.hashCode();
    if (data != null) {
      result = 31 * result + data.hashCode();
    }
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder implements LengthBuilder<IpV4InternetTimestampOption> {

    private byte length;
    private byte pointer;
    private byte overflow;
    private IpV4InternetTimestampOptionFlag flag;
    private IpV4InternetTimestampOptionData data;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV4InternetTimestampOption option) {
      this.length = option.length;
      this.pointer = option.pointer;
      this.overflow = option.overflow;
      this.flag = option.flag;
      this.data = option.data;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     * @param pointer pointer
     * @return this Builder object for method chaining.
     */
    public Builder pointer(byte pointer) {
      this.pointer = pointer;
      return this;
    }

    /**
     * @param overflow overflow
     * @return this Builder object for method chaining.
     */
    public Builder overflow(byte overflow) {
      this.overflow = overflow;
      return this;
    }

    /**
     * @param flag flag
     * @return this Builder object for method chaining.
     */
    public Builder flag(IpV4InternetTimestampOptionFlag flag) {
      this.flag = flag;
      return this;
    }

    /**
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(IpV4InternetTimestampOptionData data) {
      this.data = data;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV4InternetTimestampOption build() {
      return new IpV4InternetTimestampOption(this);
    }
  }

  /**
   * The interface representing an IPv4 internet timestamp option data. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV4InternetTimestampData newInstance(byte[] rawData,
   * int offset, int length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static interface IpV4InternetTimestampOptionData extends Serializable {

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
