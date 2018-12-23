/*_##########################################################################
  _##
  _##  Copyright (C) 2018  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * Icmpv6 mobile prefix advertisement packet.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6275">RFC 6275</a>
 * @see <a
 *     href="https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-24">ICMPv6
 *     Parameters</a>
 * @author Leo Ma
 * @since pcap4j 1.7.5
 */
public class IcmpV6MobilePrefixAdvertisementPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 7088081805293115326L;

  private final IcmpV6MobilePrefixAdvertisementHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV6MobilePrefixAdvertisementPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV6MobilePrefixAdvertisementPacket newPacket(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV6MobilePrefixAdvertisementPacket(rawData, offset, length);
  }

  private IcmpV6MobilePrefixAdvertisementPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV6MobilePrefixAdvertisementHeader(rawData, offset, length);
  }

  private IcmpV6MobilePrefixAdvertisementPacket(Builder builder) {
    this.header = new IcmpV6MobilePrefixAdvertisementHeader(builder);
  }

  @Override
  public IcmpV6MobilePrefixAdvertisementHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** */
  public static final class Builder extends AbstractBuilder {

    private short identifier;
    private boolean managedAddressConfigurationFlag;
    private boolean otherStatefulConfigurationFlag;
    private short reserved;
    private List<IpV6NeighborDiscoveryOption> options;

    /** */
    public Builder() {
      // Do nothing, just used to create a Builder without fields setting
    }

    private Builder(IcmpV6MobilePrefixAdvertisementPacket packet) {
      this.identifier = packet.header.identifier;
      this.managedAddressConfigurationFlag =
          packet.header.managedAddressConfigurationFlag; // M field
      this.otherStatefulConfigurationFlag = packet.header.otherStatefulConfigurationFlag; // O field
      this.reserved = packet.header.reserved;
      this.options = packet.header.options;
    }

    /**
     * @param identifier identifier
     * @return this Builder object for method chaining.
     */
    public Builder identifier(short identifier) {
      this.identifier = identifier;
      return this;
    }

    /**
     * @param managedAddressConfigurationFlag managedAddressConfigurationFlag
     * @return this Builder object for method chaining.
     */
    public Builder managedAddressConfigurationFlag(boolean managedAddressConfigurationFlag) {
      this.managedAddressConfigurationFlag = managedAddressConfigurationFlag;
      return this;
    }

    /**
     * @param otherStatefulConfigurationFlag otherStatefulConfigurationFlag
     * @return this Builder object for method chaining.
     */
    public Builder otherStatefulConfigurationFlag(boolean otherStatefulConfigurationFlag) {
      this.otherStatefulConfigurationFlag = otherStatefulConfigurationFlag;
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
     * @param options options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<IpV6NeighborDiscoveryOption> options) {
      this.options = options;
      return this;
    }

    @Override
    public IcmpV6MobilePrefixAdvertisementPacket build() {
      return new IcmpV6MobilePrefixAdvertisementPacket(this);
    }
  }

  /**
   * Icmpv6 mobile prefix advertisement header.
   *
   * <pre style="white-space: pre;">
   *  0                   1                   2                   3
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |          Identifier           |M|O|        Reserved           |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |           Options ...
   * +-+-+-+-+-+-+-+-+-+-+-+-+-
   * </pre>
   *
   * @see <a href="https://tools.ietf.org/html/rfc6275">RFC 6275</a>
   * @see <a
   *     href="https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-24">ICMPv6
   *     Parameters</a>
   * @author Leo Ma
   * @since pcap4j 1.7.5
   */
  public static final class IcmpV6MobilePrefixAdvertisementHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = -7395581536162987036L;

    private static final int IDENTIFIER_OFFSET = 0;
    private static final int IDENTIFIER_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int M_O_RESERVED_OFFSET = IDENTIFIER_OFFSET + IDENTIFIER_SIZE;
    private static final int M_O_RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET = M_O_RESERVED_OFFSET + M_O_RESERVED_SIZE;

    private final short identifier;
    private final boolean managedAddressConfigurationFlag; // M field
    private final boolean otherStatefulConfigurationFlag; // O field
    private final short reserved;
    private final List<IpV6NeighborDiscoveryOption> options;

    @SuppressWarnings("squid:S1166")
    private IcmpV6MobilePrefixAdvertisementHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < OPTIONS_OFFSET) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The raw data must be more than ")
            .append(OPTIONS_OFFSET - 1)
            .append("bytes")
            .append(" to build this header. raw data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      this.identifier = ByteArrays.getShort(rawData, IDENTIFIER_OFFSET + offset);
      short tmp = ByteArrays.getShort(rawData, M_O_RESERVED_OFFSET + offset);
      this.managedAddressConfigurationFlag = (tmp & 0x8000) != 0;
      this.otherStatefulConfigurationFlag = (tmp & 0x4000) != 0;
      this.reserved = (short) (0x3FFF & tmp);
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>();
      int currentOffsetInHeader = OPTIONS_OFFSET;
      while (currentOffsetInHeader < length) {
        IpV6NeighborDiscoveryOptionType type =
            IpV6NeighborDiscoveryOptionType.getInstance(rawData[currentOffsetInHeader + offset]);
        IpV6NeighborDiscoveryOption newOne;
        try {
          newOne =
              PacketFactories.getFactory(
                      IpV6NeighborDiscoveryOption.class, IpV6NeighborDiscoveryOptionType.class)
                  .newInstance(
                      rawData,
                      currentOffsetInHeader + offset,
                      length - currentOffsetInHeader,
                      type);
        } catch (Exception e) {
          break;
        }
        options.add(newOne);
        currentOffsetInHeader += newOne.length();
      }
    }

    private IcmpV6MobilePrefixAdvertisementHeader(Builder builder) {
      if ((builder.reserved & 0xC000) != 0) {
        throw new IllegalArgumentException("Invalid reserved: " + builder.reserved);
      }
      this.identifier = builder.identifier;
      this.managedAddressConfigurationFlag = builder.managedAddressConfigurationFlag;
      this.otherStatefulConfigurationFlag = builder.otherStatefulConfigurationFlag;
      this.reserved = builder.reserved;
      if (builder.options != null) {
        this.options = new ArrayList<IpV6NeighborDiscoveryOption>(builder.options);
      } else {
        this.options = new ArrayList<IpV6NeighborDiscoveryOption>(0);
      }
    }

    /** @return identifier */
    public short getIdentifier() {
      return identifier;
    }

    /** @return identifier */
    public int getIdentifierAsInt() {
      return identifier & 0xFFFF;
    }

    /** @return true if the Managed Address Configuration flag is set to 1; false otherwise. */
    public boolean getManagedAddressConfigurationFlag() {
      return managedAddressConfigurationFlag;
    }

    /** @return true if the Other Stateful Configuration flag is set to 1; false otherwise. */
    public boolean getOtherStatefulConfigurationFlag() {
      return otherStatefulConfigurationFlag;
    }

    /** @return reserved */
    public short getReserved() {
      return reserved;
    }

    /** @return options */
    public List<IpV6NeighborDiscoveryOption> getOptions() {
      return new ArrayList<IpV6NeighborDiscoveryOption>(options);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();

      rawFields.add(ByteArrays.toByteArray(identifier));
      short tmp = (short) (0x3FFF & reserved);
      if (managedAddressConfigurationFlag) {
        tmp |= 0x8000;
      }
      if (otherStatefulConfigurationFlag) {
        tmp |= 0x4000;
      }
      rawFields.add(ByteArrays.toByteArray(tmp));
      for (IpV6NeighborDiscoveryOption o : options) {
        rawFields.add(o.getRawData());
      }
      return rawFields;
    }

    @Override
    protected int calcLength() {
      int len = 0;
      for (IpV6NeighborDiscoveryOption o : options) {
        len += o.length();
      }
      return len + OPTIONS_OFFSET;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Mobile Prefix Advertisement Header (")
          .append(length())
          .append(" bytes)]")
          .append(ls);
      sb.append("  Identifier: ").append(getIdentifierAsInt()).append(ls);
      sb.append("  ManagedAddressConfigurationFlag: ")
          .append(managedAddressConfigurationFlag)
          .append(ls);
      sb.append("  OtherStatefulConfigurationFlag: ")
          .append(otherStatefulConfigurationFlag)
          .append(ls);
      sb.append("  Reserved: ").append(reserved).append(ls);
      for (IpV6NeighborDiscoveryOption opt : options) {
        sb.append("  Option: ").append(opt).append(ls);
      }

      return sb.toString();
    }

    @Override
    @SuppressWarnings("squid:S1067")
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      IcmpV6MobilePrefixAdvertisementHeader other = (IcmpV6MobilePrefixAdvertisementHeader) obj;
      return this.identifier == other.identifier
          && this.managedAddressConfigurationFlag == other.managedAddressConfigurationFlag
          && this.otherStatefulConfigurationFlag == other.otherStatefulConfigurationFlag
          && this.reserved == other.reserved
          && options.equals(other.options);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + identifier;
      result = 31 * result + (managedAddressConfigurationFlag ? 1231 : 1237);
      result = 31 * result + (otherStatefulConfigurationFlag ? 1231 : 1237);
      result = 31 * result + reserved;
      result = 31 * result + options.hashCode();
      return result;
    }
  }
}
