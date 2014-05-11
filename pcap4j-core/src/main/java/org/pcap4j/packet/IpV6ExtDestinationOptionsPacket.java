/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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
public final class IpV6ExtDestinationOptionsPacket extends IpV6ExtOptionsPacket {

  /**
   *
   */
  private static final long serialVersionUID = -3293888276359687328L;

  private final IpV6ExtDestinationOptionsHeader header;

  /**
   *
   * @param rawData
   * @return a new IpV6ExtDestinationOptionsPacket object.
   * @throws IllegalRawDataException
   */
  public static IpV6ExtDestinationOptionsPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    IpV6ExtDestinationOptionsHeader optHeader
      = new IpV6ExtDestinationOptionsHeader(rawData);
    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          optHeader.length(),
          rawData.length - optHeader.length()
        );

    return new IpV6ExtDestinationOptionsPacket(rawPayload, optHeader);
  }

  private IpV6ExtDestinationOptionsPacket(
    byte[] rawPayload, IpV6ExtDestinationOptionsHeader optHeader
  ) {
    super(rawPayload, optHeader.getNextHeader());
    this.header = optHeader;
  }

  private IpV6ExtDestinationOptionsPacket(Builder builder) {
    super(builder);
    this.header = new IpV6ExtDestinationOptionsHeader(builder);
  }

  @Override
  public IpV6ExtDestinationOptionsHeader getHeader() {
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

    private Builder(IpV6ExtDestinationOptionsPacket packet) {
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
    public IpV6ExtDestinationOptionsPacket build() {
      return new IpV6ExtDestinationOptionsPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static
  final class IpV6ExtDestinationOptionsHeader extends IpV6ExtOptionsHeader {

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
    private static final long serialVersionUID = 4686702407537705400L;

    private IpV6ExtDestinationOptionsHeader(byte[] rawData) throws IllegalRawDataException {
      super(rawData);
    }

    private IpV6ExtDestinationOptionsHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "IPv6 Destination Options Header";
    }

  }

}
