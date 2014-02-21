/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
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
public final class IcmpV6RouterAdvertisementPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -537286641023282344L;

  private final IcmpV6RouterAdvertisementHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV6RouterAdvertisementPacket object.
   */
  public static IcmpV6RouterAdvertisementPacket newPacket(byte[] rawData) {
    return new IcmpV6RouterAdvertisementPacket(rawData);
  }

  private IcmpV6RouterAdvertisementPacket(byte[] rawData) {
    this.header = new IcmpV6RouterAdvertisementHeader(rawData);
  }

  private IcmpV6RouterAdvertisementPacket(Builder builder) {
    if (
         builder == null
      || builder.options == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.options: ").append(builder.options);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV6RouterAdvertisementHeader(builder);
  }

  @Override
  public IcmpV6RouterAdvertisementHeader getHeader() {
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

    private byte curHopLimit;
    private boolean managedAddressConfigurationFlag; // M field
    private boolean otherConfigurationFlag; // O field
    private byte reserved;
    private short routerLifetime;
    private int reachableTime;
    private int retransTimer;
    private List<IpV6NeighborDiscoveryOption> options;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV6RouterAdvertisementPacket packet) {
      this.curHopLimit = packet.header.curHopLimit;
      this.managedAddressConfigurationFlag
        = packet.header.managedAddressConfigurationFlag;
      this.otherConfigurationFlag = packet.header.otherConfigurationFlag;
      this.reserved = packet.header.reserved;
      this.routerLifetime = packet.header.routerLifetime;
      this.reachableTime = packet.header.reachableTime;
      this.retransTimer = packet.header.retransTimer;
      this.options = packet.header.options;
    }

    /**
     *
     * @param curHopLimit
     * @return this Builder object for method chaining.
     */
    public Builder curHopLimit(byte curHopLimit) {
      this.curHopLimit = curHopLimit;
      return this;
    }

    /**
     *
     * @param managedAddressConfigurationFlag
     * @return this Builder object for method chaining.
     */
    public Builder managedAddressConfigurationFlag(
      boolean managedAddressConfigurationFlag
    ) {
      this.managedAddressConfigurationFlag = managedAddressConfigurationFlag;
      return this;
    }

    /**
     *
     * @param otherConfigurationFlag
     * @return this Builder object for method chaining.
     */
    public Builder otherConfigurationFlag(boolean otherConfigurationFlag) {
      this.otherConfigurationFlag = otherConfigurationFlag;
      return this;
    }

    /**
     *
     * @param reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     *
     * @param routerLifetime
     * @return this Builder object for method chaining.
     */
    public Builder routerLifetime(short routerLifetime) {
      this.routerLifetime = routerLifetime;
      return this;
    }

    /**
     *
     * @param reachableTime
     * @return this Builder object for method chaining.
     */
    public Builder reachableTime(int reachableTime) {
      this.reachableTime = reachableTime;
      return this;
    }

    /**
     *
     * @param retransTimer
     * @return this Builder object for method chaining.
     */
    public Builder retransTimer(int retransTimer) {
      this.retransTimer = retransTimer;
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
    public IcmpV6RouterAdvertisementPacket build() {
      return new IcmpV6RouterAdvertisementPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static
  final class IcmpV6RouterAdvertisementHeader extends AbstractHeader {

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                         Reachable Time                        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                          Retrans Timer                        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Options ...
     * +-+-+-+-+-+-+-+-+-+-+-+-
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = -3300835116087515662L;

    private static final int CUR_HOP_LIMIT_OFFSET
      = 0;
    private static final int CUR_HOP_LIMIT_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int M_O_RESERVED_OFFSET
      = CUR_HOP_LIMIT_OFFSET + CUR_HOP_LIMIT_SIZE;
    private static final int M_O_RESERVED_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int ROUTER_LIFETIME_OFFSET
      = M_O_RESERVED_OFFSET + M_O_RESERVED_SIZE;
    private static final int ROUTER_LIFETIME_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int REACHABLE_TIME_OFFSET
      = ROUTER_LIFETIME_OFFSET + ROUTER_LIFETIME_SIZE;
    private static final int REACHABLE_TIME_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int RETRANS_TIMER_OFFSET
      = REACHABLE_TIME_OFFSET + REACHABLE_TIME_SIZE;
    private static final int RETRANS_TIMER_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = RETRANS_TIMER_OFFSET + RETRANS_TIMER_SIZE;

    private final byte curHopLimit;
    private final boolean managedAddressConfigurationFlag; // M field
    private final boolean otherConfigurationFlag; // O field
    private final byte reserved;
    private final short routerLifetime;
    private final int reachableTime;
    private final int retransTimer;
    private final List<IpV6NeighborDiscoveryOption> options;

    private IcmpV6RouterAdvertisementHeader(byte[] rawData) {
      if (rawData.length < OPTIONS_OFFSET) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The raw data must be more than ")
          .append(OPTIONS_OFFSET - 1).append("bytes")
          .append(" to build this header. raw data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.curHopLimit = ByteArrays.getByte(rawData, CUR_HOP_LIMIT_OFFSET);
      byte tmp = ByteArrays.getByte(rawData, M_O_RESERVED_OFFSET);
      this.managedAddressConfigurationFlag = (tmp & 0x80) != 0;
      this.otherConfigurationFlag = (tmp & 0x40) != 0;
      this.reserved = (byte)(0x3F & tmp);
      this.routerLifetime = ByteArrays.getShort(rawData, ROUTER_LIFETIME_OFFSET);
      this.reachableTime = ByteArrays.getInt(rawData, REACHABLE_TIME_OFFSET);
      this.retransTimer = ByteArrays.getInt(rawData, RETRANS_TIMER_OFFSET);

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

    private IcmpV6RouterAdvertisementHeader(Builder builder) {
      if ((builder.reserved & 0xC0) != 0) {
        throw new IllegalArgumentException(
                "Invalid reserved: " + builder.reserved
              );
      }

      this.curHopLimit = builder.curHopLimit;
      this.managedAddressConfigurationFlag = builder.managedAddressConfigurationFlag;
      this.otherConfigurationFlag = builder.otherConfigurationFlag;
      this.reserved = builder.reserved;
      this.routerLifetime = builder.routerLifetime;
      this.reachableTime = builder.reachableTime;
      this.retransTimer = builder.retransTimer;
      this.options = new ArrayList<IpV6NeighborDiscoveryOption>(builder.options);
    }

    /**
     *
     * @return curHopLimit
     */
    public byte getCurHopLimit() {
      return curHopLimit;
    }

    /**
     *
     * @return curHopLimit
     */
    public int getCurHopLimitAsInt() {
      return curHopLimit & 0xFF;
    }

    /**
     *
     * @return managedAddressConfigurationFlag
     */
    public boolean getManagedAddressConfigurationFlag() {
      return managedAddressConfigurationFlag;
    }

    /**
     *
     * @return otherConfigurationFlag
     */
    public boolean getOtherConfigurationFlag() {
      return otherConfigurationFlag;
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
     * @return routerLifetime
     */
    public short getRouterLifetime() {
      return routerLifetime;
    }

    /**
     *
     * @return routerLifetime
     */
    public int getRouterLifetimeAsInt() {
      return routerLifetime & 0xFFFF;
    }

    /**
     *
     * @return reachableTime
     */
    public int getReachableTime() {
      return reachableTime;
    }

    /**
     *
     * @return reachableTime
     */
    public long getReachableTimeAsLong() {
      return reachableTime & 0xFFFFFFFFL;
    }

    /**
     *
     * @return retransTimer
     */
    public int getRetransTimer() {
      return retransTimer;
    }

    /**
     *
     * @return retransTimer
     */
    public long getRetransTimerAsLong() {
      return retransTimer & 0xFFFFFFFFL;
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
      rawFields.add(ByteArrays.toByteArray(curHopLimit));
      byte tmp = (byte)(0x3F & reserved);
      if (managedAddressConfigurationFlag) {
        tmp |= 1 << 7;
      }
      if (otherConfigurationFlag) {
        tmp |= 1 << 6;
      }
      rawFields.add(new byte[] { tmp });
      rawFields.add(ByteArrays.toByteArray(routerLifetime));
      rawFields.add(ByteArrays.toByteArray(reachableTime));
      rawFields.add(ByteArrays.toByteArray(retransTimer));
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

      sb.append("[ICMPv6 Router Advertisement Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Cur Hop Limit: ")
        .append(getCurHopLimitAsInt())
        .append(ls);
      sb.append("  Managed address configuration flag: ")
        .append(managedAddressConfigurationFlag)
        .append(ls);
      sb.append("  Other configuration flag: ")
        .append(otherConfigurationFlag)
        .append(ls);
      sb.append("  Reserved: ")
        .append(reserved)
        .append(ls);
      sb.append("  Router Lifetime: ")
        .append(getRouterLifetimeAsInt())
        .append(ls);
      sb.append("  Reachable Time: ")
        .append(getReachableTimeAsLong())
        .append(ls);
      sb.append("  Retrans Timer: ")
        .append(getRetransTimerAsLong())
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
