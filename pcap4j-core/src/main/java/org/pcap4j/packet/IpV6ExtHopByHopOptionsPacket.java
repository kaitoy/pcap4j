/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.List;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6ExtHopByHopOptionsPacket extends IpV6ExtOptionsPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4289988881526919621L;

  private final IpV6ExtHopByHopOptionsHeader header;

  /**
   *
   * @param rawData
   * @return a new IpV6ExtHopByHopOptionsPacket object.
   */
  public static IpV6ExtHopByHopOptionsPacket newPacket(byte[] rawData) {
    IpV6ExtHopByHopOptionsHeader optHeader
      = new IpV6ExtHopByHopOptionsHeader(rawData);
    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          optHeader.length(),
          rawData.length - optHeader.length()
        );

    return new IpV6ExtHopByHopOptionsPacket(rawPayload, optHeader);
  }

  private IpV6ExtHopByHopOptionsPacket(
    byte[] rawPayload, IpV6ExtHopByHopOptionsHeader optHeader
  ) {
    super(rawPayload, optHeader.getNextHeader());
    this.header = optHeader;
  }

  private IpV6ExtHopByHopOptionsPacket(Builder builder) {
    super(builder);
    this.header = new IpV6ExtHopByHopOptionsHeader(builder);
  }

  @Override
  public IpV6ExtHopByHopOptionsHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class Builder
  extends org.pcap4j.packet.IpV6ExtOptionsPacket.Builder {

    /**
     *
     */
    public Builder() {}

    private Builder(IpV6ExtHopByHopOptionsPacket packet) {
      super(packet);
    }

    @Override
    public Builder nextHeader(IpNumber nextHeader) {
      super.nextHeader(nextHeader);
      return this;
    }

    @Override
    public Builder hdrExtLen(byte hdrExtLen) {
      super.hdrExtLen(hdrExtLen);
      return this;
    }

    @Override
    public Builder options(List<IpV6Option> options) {
      super.options(options);
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      super.payloadBuilder(payloadBuilder);
      return this;
    }

    @Override
    public IpV6ExtHopByHopOptionsPacket build() {
      return new IpV6ExtHopByHopOptionsPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static
  final class IpV6ExtHopByHopOptionsHeader extends IpV6ExtOptionsHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Next Header  |  Hdr Ext Len  |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
     * |                                                               |
     * .                                                               .
     * .                            Options                            .
     * .                                                               .
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = -3903426584619413207L;

    private IpV6ExtHopByHopOptionsHeader(byte[] rawData) { super(rawData); }

    private IpV6ExtHopByHopOptionsHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "IPv6 Hop-by-Hop Options Header";
    }

  }

}
