/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
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
public final class UnknownIpV6NeighborDiscoveryOption
implements IpV6NeighborDiscoveryOption {

  /**
   *
   */
  private static final long serialVersionUID = -5097068268518944469L;

  private final IpV6NeighborDiscoveryOptionType type;
  private final byte length;
  private final byte[] data;

  /**
   *
   * @param rawData
   * @return a new UnknownIpV6NeighborDiscoveryOption object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static UnknownIpV6NeighborDiscoveryOption newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new UnknownIpV6NeighborDiscoveryOption(rawData);
  }

  private UnknownIpV6NeighborDiscoveryOption(byte[] rawData) throws IllegalRawDataException {
    if (rawData.length < 2) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 1. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.type = IpV6NeighborDiscoveryOptionType.getInstance(rawData[0]);
    this.length = rawData[1];

    this.data = ByteArrays.getSubArray(rawData, 2, length * 8 - 2);
  }

  private UnknownIpV6NeighborDiscoveryOption(Builder builder) {
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
      this.length = (byte)length();
    }
    else {
      this.length = builder.length;
    }
  }

  public IpV6NeighborDiscoveryOptionType getType() { return type; }

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
    rawData[1] = length;
    System.arraycopy(data, 0, rawData, 2, data.length);
    return rawData;
  }

  public int length() { return data.length + 2; }

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
   * @since pcap4j 0.9.15
   */
  public static final class
  Builder implements LengthBuilder<UnknownIpV6NeighborDiscoveryOption> {

    private IpV6NeighborDiscoveryOptionType type;
    private byte length;
    private byte[] data;
    private boolean correctLengthAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(UnknownIpV6NeighborDiscoveryOption option) {
      this.type = option.type;
      this.length = option.length;
      this.data = option.data;
    }

    /**
     *
     * @param type
     * @return this Builder object for method chaining.
     */
    public Builder type(IpV6NeighborDiscoveryOptionType type) {
      this.type = type;
      return this;
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

    public UnknownIpV6NeighborDiscoveryOption build() {
      return new UnknownIpV6NeighborDiscoveryOption(this);
    }

  }

}
