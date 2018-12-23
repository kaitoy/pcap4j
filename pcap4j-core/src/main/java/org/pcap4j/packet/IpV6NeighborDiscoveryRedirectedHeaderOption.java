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
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryRedirectedHeaderOption
    implements IpV6NeighborDiscoveryOption {

  /*
   *   0                   1                   2                   3
   *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |     Type      |    Length     |                               |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   *  |                           Reserved                            |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                                                               |
   *  ~                       IP header + data                        ~
   *  |                                                               |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   Type=4
   */

  /** */
  private static final long serialVersionUID = 8049779415539820332L;

  private static final int TYPE_OFFSET = 0;
  private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int LENGTH_OFFSET = TYPE_OFFSET + TYPE_SIZE;
  private static final int LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int RESERVED_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
  private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES + INT_SIZE_IN_BYTES;
  private static final int IP_HEADER_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;

  private final IpV6NeighborDiscoveryOptionType type =
      IpV6NeighborDiscoveryOptionType.REDIRECTED_HEADER;
  private final byte length;
  private final byte[] reserved;
  private final Packet ipPacket;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6NeighborDiscoveryRedirectedHeaderOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6NeighborDiscoveryRedirectedHeaderOption newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6NeighborDiscoveryRedirectedHeaderOption(rawData, offset, length);
  }

  private IpV6NeighborDiscoveryRedirectedHeaderOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < IP_HEADER_OFFSET + 40) { // IP_HEADER_OFFSET + IPv6 Header
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 47. rawData: ")
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
    if (lengthInByte < IP_HEADER_OFFSET) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The length field value must be equal or more than")
          .append(IP_HEADER_OFFSET / 8)
          .append("but it is: ")
          .append(getLengthAsInt());
      throw new IllegalRawDataException(sb.toString());
    }

    this.reserved = ByteArrays.getSubArray(rawData, RESERVED_OFFSET + offset, RESERVED_SIZE);

    Packet p =
        PacketFactories.getFactory(Packet.class, EtherType.class)
            .newInstance(
                rawData,
                IP_HEADER_OFFSET + offset,
                lengthInByte - IP_HEADER_OFFSET,
                EtherType.IPV6);
    if (p instanceof IllegalPacket) {
      this.ipPacket = p;
      return;
    } else if (p.contains(IllegalPacket.class)) {
      Packet.Builder builder = p.getBuilder();
      byte[] ipRawData = p.get(IllegalPacket.class).getRawData();
      builder
          .getOuterOf(IllegalPacket.Builder.class)
          .payloadBuilder(
              PacketFactories.getFactory(Packet.class, NotApplicable.class)
                  .newInstance(ipRawData, 0, ipRawData.length)
                  .getBuilder());
      for (Packet.Builder b : builder) {
        if (b instanceof LengthBuilder) {
          ((LengthBuilder<?>) b).correctLengthAtBuild(false);
        }
        if (b instanceof ChecksumBuilder) {
          ((ChecksumBuilder<?>) b).correctChecksumAtBuild(false);
        }
      }
      p = builder.build();
    }
    this.ipPacket = p;
  }

  private IpV6NeighborDiscoveryRedirectedHeaderOption(Builder builder) {
    if (builder == null || builder.reserved == null || builder.ipPacket == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.reserved: ")
          .append(builder.reserved)
          .append(" builder.ipPacket: ")
          .append(builder.ipPacket);
      throw new NullPointerException(sb.toString());
    }
    if (builder.reserved.length != 6) {
      throw new IllegalArgumentException(
          "Invalid reserved: " + ByteArrays.toHexString(builder.reserved, " "));
    }

    this.reserved = ByteArrays.clone(builder.reserved);
    this.ipPacket = builder.ipPacket;

    if (builder.correctLengthAtBuild) {
      if (length() % 8 != 0) {
        StringBuilder sb = new StringBuilder();
        sb.append("ipPacket's length is invalid. ipPacket: ")
            .append(ByteArrays.toHexString(ipPacket.getRawData(), " "));
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

  /** @return reserved */
  public byte[] getReserved() {
    return ByteArrays.clone(reserved);
  }

  /** @return ipPacket */
  public Packet getIpPacket() {
    return ipPacket;
  }

  @Override
  public int length() {
    return 8 + ipPacket.length();
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[TYPE_OFFSET] = getType().value();
    rawData[LENGTH_OFFSET] = length;
    System.arraycopy(reserved, 0, rawData, RESERVED_OFFSET, RESERVED_SIZE);
    System.arraycopy(ipPacket.getRawData(), 0, rawData, IP_HEADER_OFFSET, ipPacket.length());
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
    sb.append(" bytes)] [Reserved: ").append(ByteArrays.toHexString(reserved, " "));
    sb.append("] [IP header + data: {").append(ipPacket);
    sb.append("}]");
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

    IpV6NeighborDiscoveryRedirectedHeaderOption other =
        (IpV6NeighborDiscoveryRedirectedHeaderOption) obj;
    return length == other.length
        && ipPacket.equals(other.ipPacket)
        && Arrays.equals(reserved, other.reserved);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(reserved);
    result = 31 * result + ipPacket.hashCode();
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder
      implements LengthBuilder<IpV6NeighborDiscoveryRedirectedHeaderOption> {

    private byte length;
    private byte[] reserved;
    private Packet ipPacket;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV6NeighborDiscoveryRedirectedHeaderOption option) {
      this.length = option.length;
      this.reserved = option.reserved;
      this.ipPacket = option.ipPacket;
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
     * @param reserved 6 bytes
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte[] reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param ipPacket ipPacket
     * @return this Builder object for method chaining.
     */
    public Builder ipPacket(Packet ipPacket) {
      this.ipPacket = ipPacket;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6NeighborDiscoveryRedirectedHeaderOption build() {
      return new IpV6NeighborDiscoveryRedirectedHeaderOption(this);
    }
  }
}
