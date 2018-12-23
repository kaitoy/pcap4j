/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4InformationReplyPacket extends IcmpIdentifiablePacket {

  /** */
  private static final long serialVersionUID = -9187969821832140340L;

  private final IcmpV4InformationReplyHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV4InformationReplyPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV4InformationReplyPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV4InformationReplyPacket(rawData, offset, length);
  }

  private IcmpV4InformationReplyPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV4InformationReplyHeader(rawData, offset, length);
  }

  private IcmpV4InformationReplyPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4InformationReplyHeader(builder);
  }

  @Override
  public IcmpV4InformationReplyHeader getHeader() {
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
  public static final class Builder extends org.pcap4j.packet.IcmpIdentifiablePacket.Builder {

    /** */
    public Builder() {}

    @Override
    public Builder identifier(short identifier) {
      super.identifier(identifier);
      return this;
    }

    @Override
    public Builder sequenceNumber(short sequenceNumber) {
      super.sequenceNumber(sequenceNumber);
      return this;
    }

    private Builder(IcmpV4InformationReplyPacket packet) {
      super(packet);
    }

    @Override
    public IcmpV4InformationReplyPacket build() {
      return new IcmpV4InformationReplyPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4InformationReplyHeader extends IcmpIdentifiableHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = -2093444994122929555L;

    private IcmpV4InformationReplyHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      super(rawData, offset, length);
    }

    private IcmpV4InformationReplyHeader(Builder builder) {
      super(builder);
    }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Information Reply Header";
    }
  }
}
