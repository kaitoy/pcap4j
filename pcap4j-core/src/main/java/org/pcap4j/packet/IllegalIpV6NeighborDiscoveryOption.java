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
public final class IllegalIpV6NeighborDiscoveryOption
implements IpV6NeighborDiscoveryOption {

  /**
   *
   */
  private static final long serialVersionUID = 2715909582897939970L;

  private final IpV6NeighborDiscoveryOptionType type;
  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new IllegalIpV6NeighborDiscoveryOption object.
   */
  public static IllegalIpV6NeighborDiscoveryOption newInstance(byte[] rawData) {
    return new IllegalIpV6NeighborDiscoveryOption(rawData);
  }

  private IllegalIpV6NeighborDiscoveryOption(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data has no data. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalArgumentException(sb.toString());
    }

    this.type = IpV6NeighborDiscoveryOptionType.getInstance(rawData[0]);
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private IllegalIpV6NeighborDiscoveryOption(Builder builder) {
    if (
        builder == null
     || builder.type == null
     || builder.rawData == null
   ) {
     StringBuilder sb = new StringBuilder();
     sb.append("builder: ").append(builder)
       .append(" builder.type: ").append(builder.type)
       .append(" builder.rawData: ").append(builder.rawData);
     throw new NullPointerException(sb.toString());
   }

   this.type = builder.type;
   this.rawData = new byte[builder.rawData.length];
   System.arraycopy(
     builder.rawData, 0, this.rawData, 0, builder.rawData.length
   );
  }

  public IpV6NeighborDiscoveryOptionType getType() { return type; }

  public int length() { return rawData.length; }

  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
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
    sb.append("[Type: ")
      .append(type)
      .append("] [Illegal Raw Data: 0x")
      .append(ByteArrays.toHexString(rawData, ""))
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
  public static final class Builder {

    private IpV6NeighborDiscoveryOptionType type;
    private byte[] rawData;

    /**
     *
     */
    public Builder() {}

    private Builder(IllegalIpV6NeighborDiscoveryOption option) {
      this.type = option.type;
      this.rawData = option.rawData;
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
     * @param rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /**
     *
     * @return a new IllegalIpV6NeighborDiscoveryOption object.
     */
    public IllegalIpV6NeighborDiscoveryOption build() {
      return new IllegalIpV6NeighborDiscoveryOption(this);
    }

  }

}
