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
public final class IcmpV4SourceQuenchPacket extends IcmpV4UnusedPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4236818486389644290L;

  private final IcmpV4SourceQuenchHeader header;

  /**
   *
   * @param rawData
   * @return
   */
  public static IcmpV4SourceQuenchPacket newPacket(byte[] rawData) {
    return new IcmpV4SourceQuenchPacket(rawData);
  }

  private IcmpV4SourceQuenchPacket(byte[] rawData) {
    this.header = new IcmpV4SourceQuenchHeader(rawData);
  }

  private IcmpV4SourceQuenchPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4SourceQuenchHeader(builder);
  }

  @Override
  public IcmpV4SourceQuenchHeader getHeader() {
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

    private Builder(IcmpV4SourceQuenchPacket packet) {
      super(packet);
    }

    @Override
    public Builder unused(int unused) {
      super.unused(unused);
      return this;
    }

    @Override
    public IcmpV4SourceQuenchPacket build() {
      return new IcmpV4SourceQuenchPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class IcmpV4SourceQuenchHeader extends IcmpUnusedHeader {

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
    private static final long serialVersionUID = 1951530440617099199L;

    private IcmpV4SourceQuenchHeader(byte[] rawData) {
      super(rawData);
    }

    private IcmpV4SourceQuenchHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Source Quench Header";
    }

  }

}
