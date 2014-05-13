/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
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
public final class IcmpV6RouterSolicitationPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -8012525256314872386L;

  private final IcmpV6RouterSolicitationHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV6RouterSolicitationPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IcmpV6RouterSolicitationPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IcmpV6RouterSolicitationPacket(rawData);
  }

  private IcmpV6RouterSolicitationPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV6RouterSolicitationHeader(rawData);
  }

  private IcmpV6RouterSolicitationPacket(Builder builder) {
    if (
         builder == null
      || builder.options == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.options: ").append(builder.options);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV6RouterSolicitationHeader(builder);
  }

  @Override
  public IcmpV6RouterSolicitationHeader getHeader() {
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
    private List<IpV6NeighborDiscoveryOption> options;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV6RouterSolicitationPacket packet) {
      this.reserved = packet.header.reserved;
      this.options = packet.header.options;
    }

    /**
     *
     * @param reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(int reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     *
     * @param options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<IpV6NeighborDiscoveryOption> options) {
      this.options = options;
      return this;
    }

    @Override
    public IcmpV6RouterSolicitationPacket build() {
      return new IcmpV6RouterSolicitationPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static
  final class IcmpV6RouterSolicitationHeader extends AbstractHeader {

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                            Reserved                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Options ...
     * +-+-+-+-+-+-+-+-+-+-+-+-
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = -6091118158605916309L;

    private static final int RESERVED_OFFSET
      = 0;
    private static final int RESERVED_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = RESERVED_OFFSET + RESERVED_SIZE;

    private final int reserved;
    private final List<IpV6NeighborDiscoveryOption> options;

    private IcmpV6RouterSolicitationHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < OPTIONS_OFFSET) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The raw data must be more than ")
          .append(OPTIONS_OFFSET - 1).append("bytes")
          .append(" to build this header. raw data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.reserved = ByteArrays.getInt(rawData, RESERVED_OFFSET);

      this.options = new ArrayList<IpV6NeighborDiscoveryOption>();
      int currentOffset = OPTIONS_OFFSET;
      while (currentOffset < rawData.length) {
        byte[] optRawData = ByteArrays.getSubArray(
                              rawData,
                              currentOffset,
                              rawData.length - currentOffset
                            );
        IpV6NeighborDiscoveryOptionType type
          = IpV6NeighborDiscoveryOptionType.getInstance(optRawData[0]);
        IpV6NeighborDiscoveryOption newOne
          = PacketFactories
              .getFactory(
                 IpV6NeighborDiscoveryOption.class,
                 IpV6NeighborDiscoveryOptionType.class
               ).newInstance(optRawData, type);
        options.add(newOne);
        currentOffset += newOne.length();
      }
    }

    private IcmpV6RouterSolicitationHeader(Builder builder) {
      this.reserved = builder.reserved;
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>(builder.options);
    }

    /**
     *
     * @return reserved
     */
    public int getReserved() {
      return reserved;
    }

    /**
     *
     * @return options
     */
    public List<IpV6NeighborDiscoveryOption> getOptions() {
      return new ArrayList<IpV6NeighborDiscoveryOption>(options);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(reserved));
      for (IpV6NeighborDiscoveryOption o: options) {
        rawFields.add(o.getRawData());
      }
      return rawFields;
    }

    @Override
    protected int calcLength() {
      int len = 0;
      for (IpV6NeighborDiscoveryOption o: options) {
        len += o.length();
      }
      return len + OPTIONS_OFFSET;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Router Solicitation Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Reserved: ")
        .append(reserved)
        .append(ls);
      for (IpV6NeighborDiscoveryOption opt: options) {
        sb.append("  Option: ")
          .append(opt)
          .append(ls);
      }

      return sb.toString();
    }

  }

}
