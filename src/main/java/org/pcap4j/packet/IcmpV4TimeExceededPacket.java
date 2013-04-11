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
public final class IcmpV4TimeExceededPacket extends IcmpV4UnusedPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4186314279255762737L;

  private final IcmpV4TimeExceededHeader header;

  /**
   *
   * @param rawData
   * @return
   */
  public static IcmpV4TimeExceededPacket newPacket(byte[] rawData) {
    return new IcmpV4TimeExceededPacket(rawData);
  }

  private IcmpV4TimeExceededPacket(byte[] rawData) {
    this.header = new IcmpV4TimeExceededHeader(rawData);
  }

  private IcmpV4TimeExceededPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4TimeExceededHeader(builder);
  }

  @Override
  public IcmpV4TimeExceededHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

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

    private Builder(IcmpV4TimeExceededPacket packet) {
      super(packet);
    }

    @Override
    public Builder unused(int unused) {
      super.unused(unused);
      return this;
    }

    @Override
    public IcmpV4TimeExceededPacket build() {
      return new IcmpV4TimeExceededPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class IcmpV4TimeExceededHeader extends IcmpUnusedHeader {

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
    private static final long serialVersionUID = 4981354953509735577L;

    private IcmpV4TimeExceededHeader(byte[] rawData) {
      super(rawData);
    }

    private IcmpV4TimeExceededHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Time Exceeded Header";
    }

  }

}
