/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryMtuOption implements IpV6NeighborDiscoveryOption {

  /*
   *   0                   1                   2                   3
   *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |     Type      |    Length     |           Reserved            |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                              MTU                              |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   Type=5
   */

  /** */
  private static final long serialVersionUID = 4145831782727036195L;

  private static final int TYPE_OFFSET = 0;
  private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int LENGTH_OFFSET = TYPE_OFFSET + TYPE_SIZE;
  private static final int LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int RESERVED_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
  private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
  private static final int MTU_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
  private static final int MTU_SIZE = INT_SIZE_IN_BYTES;
  private static final int IPV6_NEIGHBOR_DISCOVERY_MTU_OPTION_SIZE = MTU_OFFSET + MTU_SIZE;

  private final IpV6NeighborDiscoveryOptionType type = IpV6NeighborDiscoveryOptionType.MTU;
  private final byte length;
  private final short reserved;
  private final int mtu;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6NeighborDiscoveryMtuOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6NeighborDiscoveryMtuOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6NeighborDiscoveryMtuOption(rawData, offset, length);
  }

  private IpV6NeighborDiscoveryMtuOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < IPV6_NEIGHBOR_DISCOVERY_MTU_OPTION_SIZE) {
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
    int lengthFieldAsInt = getLengthAsInt();
    if (lengthFieldAsInt * 8 != IPV6_NEIGHBOR_DISCOVERY_MTU_OPTION_SIZE) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Illegal value in the length field: ").append(lengthFieldAsInt);
      throw new IllegalRawDataException(sb.toString());
    }

    this.reserved = ByteArrays.getShort(rawData, RESERVED_OFFSET + offset);
    this.mtu = ByteArrays.getInt(rawData, MTU_OFFSET + offset);
  }

  private IpV6NeighborDiscoveryMtuOption(Builder builder) {
    if (builder == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);
      throw new NullPointerException(sb.toString());
    }

    this.reserved = builder.reserved;
    this.mtu = builder.mtu;

    if (builder.correctLengthAtBuild) {
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

  /** @return reserved */
  public short getReserved() {
    return reserved;
  }

  /** @return mtu */
  public int getMtu() {
    return mtu;
  }

  /** @return mtu */
  public long getMtuAsLong() {
    return mtu & 0xFFFFFFFFL;
  }

  @Override
  public int length() {
    return IPV6_NEIGHBOR_DISCOVERY_MTU_OPTION_SIZE;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[TYPE_OFFSET] = getType().value();
    rawData[LENGTH_OFFSET] = length;
    System.arraycopy(ByteArrays.toByteArray(reserved), 0, rawData, RESERVED_OFFSET, RESERVED_SIZE);
    System.arraycopy(ByteArrays.toByteArray(mtu), 0, rawData, MTU_OFFSET, MTU_SIZE);
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
    sb.append(" bytes)] [Reserved: ").append(reserved);
    sb.append("] [MTU: ").append(getMtuAsLong());
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

    IpV6NeighborDiscoveryMtuOption other = (IpV6NeighborDiscoveryMtuOption) obj;
    return mtu == other.mtu && length == other.length && reserved == other.reserved;
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + reserved;
    result = 31 * result + mtu;
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder implements LengthBuilder<IpV6NeighborDiscoveryMtuOption> {

    private byte length;
    private short reserved;
    private int mtu;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV6NeighborDiscoveryMtuOption option) {
      this.length = option.length;
      this.reserved = option.reserved;
      this.mtu = option.mtu;
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
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(short reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param mtu mtu
     * @return this Builder object for method chaining.
     */
    public Builder mtu(int mtu) {
      this.mtu = mtu;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6NeighborDiscoveryMtuOption build() {
      return new IpV6NeighborDiscoveryMtuOption(this);
    }
  }
}
