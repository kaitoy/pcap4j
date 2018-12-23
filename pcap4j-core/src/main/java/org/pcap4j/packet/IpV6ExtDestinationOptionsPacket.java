/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
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

  /** */
  private static final long serialVersionUID = -3293888276359687328L;

  private final IpV6ExtDestinationOptionsHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6ExtDestinationOptionsPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6ExtDestinationOptionsPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    IpV6ExtDestinationOptionsHeader optHeader =
        new IpV6ExtDestinationOptionsHeader(rawData, offset, length);

    int payloadLength = length - optHeader.length();
    if (payloadLength > 0) {
      return new IpV6ExtDestinationOptionsPacket(
          rawData, offset + optHeader.length(), payloadLength, optHeader);
    } else {
      return new IpV6ExtDestinationOptionsPacket(optHeader);
    }
  }

  private IpV6ExtDestinationOptionsPacket(IpV6ExtDestinationOptionsHeader optHeader) {
    this.header = optHeader;
  }

  private IpV6ExtDestinationOptionsPacket(
      byte[] rawData,
      int payloadOffset,
      int payloadLength,
      IpV6ExtDestinationOptionsHeader optHeader) {
    super(rawData, payloadOffset, payloadLength, optHeader.getNextHeader());
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
  public static final class Builder extends org.pcap4j.packet.IpV6ExtOptionsPacket.Builder {

    /** */
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
  public static final class IpV6ExtDestinationOptionsHeader extends IpV6ExtOptionsHeader {

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

    /** */
    private static final long serialVersionUID = 4686702407537705400L;

    private IpV6ExtDestinationOptionsHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);
    }

    private IpV6ExtDestinationOptionsHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "IPv6 Destination Options Header";
    }
  }
}
