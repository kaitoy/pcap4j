/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet6Address;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryPrefixInformationOption
    implements IpV6NeighborDiscoveryOption {

  /*
   *   0                   1                   2                   3
   *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                         Valid Lifetime                        |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                       Preferred Lifetime                      |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           Reserved2                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                                                               |
   *  +                                                               +
   *  |                                                               |
   *  +                            Prefix                             +
   *  |                                                               |
   *  +                                                               +
   *  |                                                               |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   Type=3
   */

  /** */
  private static final long serialVersionUID = -1397830548673996516L;

  private static final int TYPE_OFFSET = 0;
  private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int LENGTH_OFFSET = TYPE_OFFSET + TYPE_SIZE;
  private static final int LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int PREFIX_LENGTH_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
  private static final int PREFIX_LENGTH_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int L_A_RESERVED1_OFFSET = PREFIX_LENGTH_OFFSET + PREFIX_LENGTH_SIZE;
  private static final int L_A_RESERVED1_SIZE = BYTE_SIZE_IN_BYTES;
  private static final int VALID_LIFETIME_OFFSET = L_A_RESERVED1_OFFSET + L_A_RESERVED1_SIZE;
  private static final int VALID_LIFETIME_SIZE = INT_SIZE_IN_BYTES;
  private static final int PREFERRED_LIFETIME_OFFSET = VALID_LIFETIME_OFFSET + VALID_LIFETIME_SIZE;
  private static final int PREFERRED_LIFETIME_SIZE = INT_SIZE_IN_BYTES;
  private static final int RESERVED2_OFFSET = PREFERRED_LIFETIME_OFFSET + PREFERRED_LIFETIME_SIZE;
  private static final int RESERVED2_SIZE = INT_SIZE_IN_BYTES;
  private static final int PREFIX_OFFSET = RESERVED2_OFFSET + RESERVED2_SIZE;
  private static final int PREFIX_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
  private static final int IPV6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_OPTION_SIZE =
      PREFIX_OFFSET + PREFIX_SIZE;

  private final IpV6NeighborDiscoveryOptionType type =
      IpV6NeighborDiscoveryOptionType.PREFIX_INFORMATION;
  private final byte length;
  private final byte prefixLength;
  private final boolean onLinkFlag; // L field
  private final boolean addressConfigurationFlag; // A field
  private final byte reserved1;
  private final int validLifetime;
  private final int preferredLifetime;
  private final int reserved2;
  private final Inet6Address prefix;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6NeighborDiscoveryPrefixInformationOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6NeighborDiscoveryPrefixInformationOption newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6NeighborDiscoveryPrefixInformationOption(rawData, offset, length);
  }

  private IpV6NeighborDiscoveryPrefixInformationOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < IPV6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_OPTION_SIZE) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 31. rawData: ")
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
    if (lengthFieldAsInt * 8 != IPV6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_OPTION_SIZE) {
      throw new IllegalRawDataException("Invalid value of length field: " + lengthFieldAsInt);
    }

    this.prefixLength = ByteArrays.getByte(rawData, PREFIX_LENGTH_OFFSET + offset);
    byte tmp = ByteArrays.getByte(rawData, L_A_RESERVED1_OFFSET + offset);
    this.onLinkFlag = (tmp & 0x80) != 0;
    this.addressConfigurationFlag = (tmp & 0x40) != 0;
    this.reserved1 = (byte) (0x3F & tmp);
    this.validLifetime = ByteArrays.getInt(rawData, VALID_LIFETIME_OFFSET + offset);
    this.preferredLifetime = ByteArrays.getInt(rawData, PREFERRED_LIFETIME_OFFSET + offset);
    this.reserved2 = ByteArrays.getInt(rawData, RESERVED2_OFFSET + offset);
    this.prefix = ByteArrays.getInet6Address(rawData, PREFIX_OFFSET + offset);
  }

  private IpV6NeighborDiscoveryPrefixInformationOption(Builder builder) {
    if (builder == null || builder.prefix == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.prefix: ").append(builder.prefix);
      throw new NullPointerException(sb.toString());
    }
    if ((builder.reserved1 & 0xC0) != 0) {
      throw new IllegalArgumentException("Invalid reserved1: " + builder.reserved1);
    }

    this.prefixLength = builder.prefixLength;
    this.onLinkFlag = builder.onLinkFlag;
    this.addressConfigurationFlag = builder.addressConfigurationFlag;
    this.reserved1 = builder.reserved1;
    this.validLifetime = builder.validLifetime;
    this.preferredLifetime = builder.preferredLifetime;
    this.reserved2 = builder.reserved2;
    this.prefix = builder.prefix;

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

  /** @return prefixLength */
  public byte getPrefixLength() {
    return prefixLength;
  }

  /** @return prefixLength */
  public int getPrefixLengthAsInt() {
    return 0xFF & prefixLength;
  }

  /** @return onLinkFlag */
  public boolean getOnLinkFlag() {
    return onLinkFlag;
  }

  /** @return addressConfigurationFlag */
  public boolean getAddressConfigurationFlag() {
    return addressConfigurationFlag;
  }

  /** @return reserved1 */
  public byte getReserved1() {
    return reserved1;
  }

  /** @return validLifetime */
  public int getValidLifetime() {
    return validLifetime;
  }

  /** @return validLifetime */
  public long getValidLifetimeAsLong() {
    return validLifetime & 0xFFFFFFFFL;
  }

  /** @return preferredLifetime */
  public int getPreferredLifetime() {
    return preferredLifetime;
  }

  /** @return preferredLifetime */
  public long getPreferredLifetimeAsLong() {
    return preferredLifetime & 0xFFFFFFFFL;
  }

  /** @return reserved2 */
  public int getReserved2() {
    return reserved2;
  }

  /** @return prefix */
  public Inet6Address getPrefix() {
    return prefix;
  }

  @Override
  public int length() {
    return IPV6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_OPTION_SIZE;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[TYPE_OFFSET] = getType().value();
    rawData[LENGTH_OFFSET] = length;
    rawData[PREFIX_LENGTH_OFFSET] = prefixLength;
    rawData[L_A_RESERVED1_OFFSET] = (byte) (0x3F & reserved1);
    if (onLinkFlag) {
      rawData[L_A_RESERVED1_OFFSET] |= 1 << 7;
    }
    if (addressConfigurationFlag) {
      rawData[L_A_RESERVED1_OFFSET] |= 1 << 6;
    }
    System.arraycopy(
        ByteArrays.toByteArray(validLifetime),
        0,
        rawData,
        VALID_LIFETIME_OFFSET,
        VALID_LIFETIME_SIZE);
    System.arraycopy(
        ByteArrays.toByteArray(preferredLifetime),
        0,
        rawData,
        PREFERRED_LIFETIME_OFFSET,
        PREFERRED_LIFETIME_SIZE);
    System.arraycopy(
        ByteArrays.toByteArray(reserved2), 0, rawData, RESERVED2_OFFSET, RESERVED2_SIZE);
    System.arraycopy(ByteArrays.toByteArray(prefix), 0, rawData, PREFIX_OFFSET, PREFIX_SIZE);
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
    sb.append(" bytes)] [Prefix Length: ").append(getPrefixLengthAsInt());
    sb.append("] [on-link flag: ").append(getOnLinkFlag());
    sb.append("] [address-configuration flag: ").append(getAddressConfigurationFlag());
    sb.append("] [Reserved1: ").append(getReserved1());
    sb.append("] [Valid Lifetime: ").append(getValidLifetimeAsLong());
    sb.append("] [Preferred Lifetime: ").append(getPreferredLifetimeAsLong());
    sb.append("] [Reserved2: ").append(getReserved2());
    sb.append("] [Prefix: ").append(getPrefix());
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

    IpV6NeighborDiscoveryPrefixInformationOption other =
        (IpV6NeighborDiscoveryPrefixInformationOption) obj;
    return prefix.equals(other.prefix)
        && prefixLength == other.prefixLength
        && validLifetime == other.validLifetime
        && preferredLifetime == other.preferredLifetime
        && onLinkFlag == other.onLinkFlag
        && addressConfigurationFlag == other.addressConfigurationFlag
        && reserved1 == other.reserved1
        && reserved2 == other.reserved2
        && length == other.length;
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + prefixLength;
    result = 31 * result + (onLinkFlag ? 1231 : 1237);
    result = 31 * result + (addressConfigurationFlag ? 1231 : 1237);
    result = 31 * result + reserved1;
    result = 31 * result + validLifetime;
    result = 31 * result + preferredLifetime;
    result = 31 * result + reserved2;
    result = 31 * result + prefix.hashCode();
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder
      implements LengthBuilder<IpV6NeighborDiscoveryPrefixInformationOption> {

    private byte length;
    private byte prefixLength;
    private boolean onLinkFlag; // L field
    private boolean addressConfigurationFlag; // A field
    private byte reserved1;
    private int validLifetime;
    private int preferredLifetime;
    private int reserved2;
    private Inet6Address prefix;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV6NeighborDiscoveryPrefixInformationOption option) {
      this.length = option.length;
      this.prefixLength = option.prefixLength;
      this.onLinkFlag = option.onLinkFlag;
      this.addressConfigurationFlag = option.addressConfigurationFlag;
      this.reserved1 = option.reserved1;
      this.validLifetime = option.validLifetime;
      this.preferredLifetime = option.preferredLifetime;
      this.reserved2 = option.reserved2;
      this.prefix = option.prefix;
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
     * @param prefixLength prefixLength
     * @return this Builder object for method chaining.
     */
    public Builder prefixLength(byte prefixLength) {
      this.prefixLength = prefixLength;
      return this;
    }

    /**
     * @param onLinkFlag onLinkFlag
     * @return this Builder object for method chaining.
     */
    public Builder onLinkFlag(boolean onLinkFlag) {
      this.onLinkFlag = onLinkFlag;
      return this;
    }

    /**
     * @param addressConfigurationFlag addressConfigurationFlag
     * @return this Builder object for method chaining.
     */
    public Builder addressConfigurationFlag(boolean addressConfigurationFlag) {
      this.addressConfigurationFlag = addressConfigurationFlag;
      return this;
    }

    /**
     * @param reserved1 reserved1
     * @return this Builder object for method chaining.
     */
    public Builder reserved1(byte reserved1) {
      this.reserved1 = reserved1;
      return this;
    }

    /**
     * @param validLifetime validLifetime
     * @return this Builder object for method chaining.
     */
    public Builder validLifetime(int validLifetime) {
      this.validLifetime = validLifetime;
      return this;
    }

    /**
     * @param preferredLifetime preferredLifetime
     * @return this Builder object for method chaining.
     */
    public Builder preferredLifetime(int preferredLifetime) {
      this.preferredLifetime = preferredLifetime;
      return this;
    }

    /**
     * @param reserved2 reserved2
     * @return this Builder object for method chaining.
     */
    public Builder reserved2(int reserved2) {
      this.reserved2 = reserved2;
      return this;
    }

    /**
     * @param prefix prefix
     * @return this Builder object for method chaining.
     */
    public Builder prefix(Inet6Address prefix) {
      this.prefix = prefix;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6NeighborDiscoveryPrefixInformationOption build() {
      return new IpV6NeighborDiscoveryPrefixInformationOption(this);
    }
  }
}
