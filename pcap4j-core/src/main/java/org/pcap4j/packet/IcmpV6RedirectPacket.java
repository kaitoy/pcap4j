/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6RedirectPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 3400190218684481961L;

  private final IcmpV6RedirectHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV6RedirectPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV6RedirectPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV6RedirectPacket(rawData, offset, length);
  }

  private IcmpV6RedirectPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV6RedirectHeader(rawData, offset, length);
  }

  private IcmpV6RedirectPacket(Builder builder) {
    if (builder == null
        || builder.targetAddress == null
        || builder.destinationAddress == null
        || builder.options == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.targetAddress: ")
          .append(builder.targetAddress)
          .append(" builder.destinationAddress: ")
          .append(builder.destinationAddress)
          .append(" builder.options: ")
          .append(builder.options);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV6RedirectHeader(builder);
  }

  @Override
  public IcmpV6RedirectHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder extends AbstractBuilder {

    private int reserved;
    private Inet6Address targetAddress;
    private Inet6Address destinationAddress;
    private List<IpV6NeighborDiscoveryOption> options;

    /** */
    public Builder() {}

    private Builder(IcmpV6RedirectPacket packet) {
      this.reserved = packet.header.reserved;
      this.targetAddress = packet.header.targetAddress;
      this.destinationAddress = packet.header.destinationAddress;
      this.options = packet.header.options;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(int reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param targetAddress targetAddress
     * @return this Builder object for method chaining.
     */
    public Builder targetAddress(Inet6Address targetAddress) {
      this.targetAddress = targetAddress;
      return this;
    }

    /**
     * @param destinationAddress destinationAddress
     * @return this Builder object for method chaining.
     */
    public Builder destinationAddress(Inet6Address destinationAddress) {
      this.destinationAddress = destinationAddress;
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
    public IcmpV6RedirectPacket build() {
      return new IcmpV6RedirectPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class IcmpV6RedirectHeader extends AbstractHeader {

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                           Reserved                            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                       Target Address                          +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                     Destination Address                       +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Options ...
     * +-+-+-+-+-+-+-+-+-+-+-+-
     *
     */

    /** */
    private static final long serialVersionUID = -649348640271386853L;

    private static final int RESERVED_OFFSET = 0;
    private static final int RESERVED_SIZE = INT_SIZE_IN_BYTES;
    private static final int TARGET_ADDRESS_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int TARGET_ADDRESS_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int DESTINATION_ADDRESS_OFFSET =
        TARGET_ADDRESS_OFFSET + TARGET_ADDRESS_SIZE;
    private static final int DESTINATION_ADDRESS_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET = DESTINATION_ADDRESS_OFFSET + DESTINATION_ADDRESS_SIZE;

    private final int reserved;
    private final Inet6Address targetAddress;
    private final Inet6Address destinationAddress;
    private final List<IpV6NeighborDiscoveryOption> options;

    private IcmpV6RedirectHeader(byte[] rawData, int offset, int length)
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

      this.reserved = ByteArrays.getInt(rawData, RESERVED_OFFSET + offset);
      this.targetAddress = ByteArrays.getInet6Address(rawData, TARGET_ADDRESS_OFFSET + offset);
      this.destinationAddress =
          ByteArrays.getInet6Address(rawData, DESTINATION_ADDRESS_OFFSET + offset);
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

    private IcmpV6RedirectHeader(Builder builder) {
      this.reserved = builder.reserved;
      this.targetAddress = builder.targetAddress;
      this.destinationAddress = builder.destinationAddress;
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>(builder.options);
    }

    /** @return reserved */
    public int getReserved() {
      return reserved;
    }

    /** @return targetAddress */
    public Inet6Address getTargetAddress() {
      return targetAddress;
    }

    /** @return destinationAddress */
    public Inet6Address getDestinationAddress() {
      return destinationAddress;
    }

    /** @return options */
    public List<IpV6NeighborDiscoveryOption> getOptions() {
      return new ArrayList<IpV6NeighborDiscoveryOption>(options);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(reserved));
      rawFields.add(ByteArrays.toByteArray(targetAddress));
      rawFields.add(ByteArrays.toByteArray(destinationAddress));
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

      sb.append("[ICMPv6 Redirect Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Reserved: ").append(reserved).append(ls);
      sb.append("  Target Address: ").append(targetAddress).append(ls);
      sb.append("  Destination Address: ").append(destinationAddress).append(ls);
      for (IpV6NeighborDiscoveryOption opt : options) {
        sb.append("  Option: ").append(opt).append(ls);
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

      IcmpV6RedirectHeader other = (IcmpV6RedirectHeader) obj;
      return targetAddress.equals(other.targetAddress)
          && destinationAddress.equals(other.destinationAddress)
          && reserved == other.reserved
          && options.equals(other.options);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + reserved;
      result = 31 * result + targetAddress.hashCode();
      result = 31 * result + destinationAddress.hashCode();
      result = 31 * result + options.hashCode();
      return result;
    }
  }
}
