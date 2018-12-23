/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.Arrays;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryTargetLinkLayerAddressOption
    implements IpV6NeighborDiscoveryOption {

  /*
   *   0                   1                   2                   3
   *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |     Type      |    Length     |    Link-Layer Address ...
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   Type=2
   */

  /** */
  private static final long serialVersionUID = 172728262141108390L;

  private static final int TYPE_OFFSET = 0;
  private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int LENGTH_OFFSET = TYPE_OFFSET + TYPE_SIZE;
  private static final int LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int LINK_LAYER_ADDRESS_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;

  private final IpV6NeighborDiscoveryOptionType type =
      IpV6NeighborDiscoveryOptionType.TARGET_LINK_LAYER_ADDRESS;
  private final byte length;
  private final byte[] linkLayerAddress;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6NeighborDiscoveryTargetLinkLayerAddressOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6NeighborDiscoveryTargetLinkLayerAddressOption newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6NeighborDiscoveryTargetLinkLayerAddressOption(rawData, offset, length);
  }

  private IpV6NeighborDiscoveryTargetLinkLayerAddressOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 8) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 7. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[TYPE_OFFSET + offset] != getType().value()) {
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

    this.length = rawData[LENGTH_OFFSET + offset];
    int lengthInByte = getLengthAsInt() * 8;
    if (length < lengthInByte) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option. ")
          .append(lengthInByte)
          .append(" bytes data is needed. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (this.length == 0) {
      throw new IllegalRawDataException("The length field value must not be zero.");
    }

    this.linkLayerAddress =
        ByteArrays.getSubArray(
            rawData, LINK_LAYER_ADDRESS_OFFSET + offset, lengthInByte - LINK_LAYER_ADDRESS_OFFSET);
  }

  private IpV6NeighborDiscoveryTargetLinkLayerAddressOption(Builder builder) {
    if (builder == null || builder.linkLayerAddress == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.linkLayerAddress: ")
          .append(builder.linkLayerAddress);
      throw new NullPointerException(sb.toString());
    }

    this.linkLayerAddress = new byte[builder.linkLayerAddress.length];
    System.arraycopy(
        builder.linkLayerAddress, 0, this.linkLayerAddress, 0, builder.linkLayerAddress.length);

    if (builder.correctLengthAtBuild) {
      if (length() % 8 != 0) {
        StringBuilder sb = new StringBuilder();
        sb.append("linkLayerAddress's length is invalid. linkLayerAddress: ")
            .append(ByteArrays.toHexString(linkLayerAddress, " "));
        throw new IllegalArgumentException(sb.toString());
      }
      this.length = (byte) (length() / 8);
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

  /** @return linkLayerAddress */
  public byte[] getLinkLayerAddress() {
    byte[] copy = new byte[linkLayerAddress.length];
    System.arraycopy(linkLayerAddress, 0, copy, 0, linkLayerAddress.length);
    return copy;
  }

  /** @return a MacAddress object */
  public MacAddress getLinkLayerAddressAsMacAddress() {
    return MacAddress.getByAddress(linkLayerAddress);
  }

  @Override
  public int length() {
    return linkLayerAddress.length + 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[TYPE_OFFSET] = getType().value();
    rawData[LENGTH_OFFSET] = length;
    System.arraycopy(
        linkLayerAddress, 0, rawData, LINK_LAYER_ADDRESS_OFFSET, linkLayerAddress.length);
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Type: ").append(getType());
    sb.append("] [Length: ").append(getLengthAsInt()).append(" (").append(getLengthAsInt() * 8);
    sb.append(" bytes)] [linkLayerAddress: ").append(ByteArrays.toHexString(linkLayerAddress, " "));
    sb.append("]");
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

    IpV6NeighborDiscoveryTargetLinkLayerAddressOption other =
        (IpV6NeighborDiscoveryTargetLinkLayerAddressOption) obj;
    return length == other.length && Arrays.equals(linkLayerAddress, other.linkLayerAddress);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(linkLayerAddress);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder
      implements LengthBuilder<IpV6NeighborDiscoveryTargetLinkLayerAddressOption> {

    private byte length;
    private byte[] linkLayerAddress;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV6NeighborDiscoveryTargetLinkLayerAddressOption option) {
      this.length = option.length;
      this.linkLayerAddress = option.linkLayerAddress;
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
     * @param linkLayerAddress linkLayerAddress
     * @return this Builder object for method chaining.
     */
    public Builder linkLayerAddress(byte[] linkLayerAddress) {
      this.linkLayerAddress = linkLayerAddress;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6NeighborDiscoveryTargetLinkLayerAddressOption build() {
      return new IpV6NeighborDiscoveryTargetLinkLayerAddressOption(this);
    }
  }
}
