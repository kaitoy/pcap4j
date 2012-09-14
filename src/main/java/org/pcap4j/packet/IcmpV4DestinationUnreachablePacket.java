/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4DestinationUnreachablePacket extends IcmpV4UnusedPacket {

  /**
   *
   */
  private static final long serialVersionUID = -8841091974928291870L;

  private final IcmpV4DestinationUnreachableHeader header;

  /**
   *
   * @param rawData
   * @return
   */
  public static IcmpV4DestinationUnreachablePacket newPacket(byte[] rawData) {
    return new IcmpV4DestinationUnreachablePacket(rawData);
  }

  private IcmpV4DestinationUnreachablePacket(byte[] rawData) {
    this.header = new IcmpV4DestinationUnreachableHeader(rawData);
  }

  private IcmpV4DestinationUnreachablePacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4DestinationUnreachableHeader(builder);
  }

  @Override
  public IcmpV4DestinationUnreachableHeader getHeader() { return header; }

  @Override
  public Builder getBuilder() { return new Builder(this); }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class Builder extends org.pcap4j.packet.IcmpV4UnusedPacket.Builder {

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4DestinationUnreachablePacket packet) {
      super(packet);
    }

    @Override
    public Builder unused(int unused) {
      super.unused(unused);
      return this;
    }

    @Override
    public IcmpV4DestinationUnreachablePacket build() {
      return new IcmpV4DestinationUnreachablePacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class IcmpV4DestinationUnreachableHeader extends IcmpUnusedHeader {

    /*
     *   0                            15                              31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                             unused                            |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |IPv4 Header + 64 bits of Original Data Datagram(invokingPacket)|
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 5107806272393291695L;

    private IcmpV4DestinationUnreachableHeader(byte[] rawData) {
      super(rawData);
    }

    private IcmpV4DestinationUnreachableHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Destination Unreachable Header";
    }

  }

}
