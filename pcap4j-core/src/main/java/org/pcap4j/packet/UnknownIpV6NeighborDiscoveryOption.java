/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class UnknownIpV6NeighborDiscoveryOption implements IpV6NeighborDiscoveryOption {

  /** */
  private static final long serialVersionUID = -5097068268518944469L;

  private final IpV6NeighborDiscoveryOptionType type;
  private final byte length;
  private final byte[] data;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownIpV6NeighborDiscoveryOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownIpV6NeighborDiscoveryOption newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownIpV6NeighborDiscoveryOption(rawData, offset, length);
  }

  private UnknownIpV6NeighborDiscoveryOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 1. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.type = IpV6NeighborDiscoveryOptionType.getInstance(rawData[offset]);
    this.length = rawData[1 + offset];
    if (length < this.length * 8) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
          .append(this.length * 8)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.data = ByteArrays.getSubArray(rawData, 2 + offset, this.length * 8 - 2);
  }

  private UnknownIpV6NeighborDiscoveryOption(Builder builder) {
    if (builder == null || builder.type == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.type: ")
          .append(builder.type)
          .append(" builder.data: ")
          .append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.type = builder.type;
    this.data = new byte[builder.data.length];
    System.arraycopy(builder.data, 0, this.data, 0, builder.data.length);

    if (builder.correctLengthAtBuild) {
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public IpV6NeighborDiscoveryOptionType getType() {
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

  /** @return data */
  public byte[] getData() {
    byte[] copy = new byte[data.length];
    System.arraycopy(data, 0, copy, 0, data.length);
    return copy;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = type.value();
    rawData[1] = length;
    System.arraycopy(data, 0, rawData, 2, data.length);
    return rawData;
  }

  @Override
  public int length() {
    return data.length + 2;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Type: ")
        .append(type)
        .append("] [Length: ")
        .append(getLengthAsInt())
        .append(" bytes] [Data: 0x")
        .append(ByteArrays.toHexString(data, ""))
        .append("]");
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

    UnknownIpV6NeighborDiscoveryOption other = (UnknownIpV6NeighborDiscoveryOption) obj;
    return type.equals(other.type) && length == other.length && Arrays.equals(data, other.data);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + type.hashCode();
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(data);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder implements LengthBuilder<UnknownIpV6NeighborDiscoveryOption> {

    private IpV6NeighborDiscoveryOptionType type;
    private byte length;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownIpV6NeighborDiscoveryOption option) {
      this.type = option.type;
      this.length = option.length;
      this.data = option.data;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV6NeighborDiscoveryOptionType type) {
      this.type = type;
      return this;
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
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(byte[] data) {
      this.data = data;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public UnknownIpV6NeighborDiscoveryOption build() {
      return new UnknownIpV6NeighborDiscoveryOption(this);
    }
  }
}
