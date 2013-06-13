/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6PacketTooBigPacket
extends IcmpV6InvokingPacketPacket {

  /**
   *
   */
  private static final long serialVersionUID = -8558258364388627250L;

  private final IcmpV6PacketTooBigHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV6PacketTooBigPacket object.
   */
  public static IcmpV6PacketTooBigPacket newPacket(byte[] rawData) {
    IcmpV6PacketTooBigHeader header
      = new IcmpV6PacketTooBigHeader(rawData);
    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );
    return new IcmpV6PacketTooBigPacket(header, rawPayload);
  }

  private IcmpV6PacketTooBigPacket(
    IcmpV6PacketTooBigHeader header, byte[] rawData
  ) {
    super(rawData);
    this.header = header;
  }

  private IcmpV6PacketTooBigPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV6PacketTooBigHeader(builder);
  }

  @Override
  public IcmpV6PacketTooBigHeader getHeader() {
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
  public static
  final class Builder extends org.pcap4j.packet.IcmpV6InvokingPacketPacket.Builder {

    private int mtu;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV6PacketTooBigPacket packet) {
      super(packet);
      this.mtu = packet.getHeader().mtu;
    }

    /**
     *
     * @param mtu
     * @return this Builder object for method chaining.
     */
    public Builder mtu(int mtu) {
      this.mtu = mtu;
      return this;
    }

    @Override
    public Builder payload(Packet payload) {
      super.payload(payload);
      return this;
    }

    @Override
    public IcmpV6PacketTooBigPacket build() {
      return new IcmpV6PacketTooBigPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class IcmpV6PacketTooBigHeader extends AbstractHeader {

    /*
     *   0                            15                              31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                             MTU                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 8034982803428261280L;

    private static final int MTU_OFFSET
      = 0;
    private static final int MTU_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int ICMPV6_PACKET_TOO_BIG_HEADER_SIZE
      = MTU_OFFSET + MTU_SIZE;

    private final int mtu;

    private IcmpV6PacketTooBigHeader(byte[] rawData) {
      if (rawData.length < ICMPV6_PACKET_TOO_BIG_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv6 Packet Too Big Header(")
          .append(ICMPV6_PACKET_TOO_BIG_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.mtu = ByteArrays.getInt(rawData, MTU_OFFSET);
    }

    private IcmpV6PacketTooBigHeader(Builder builder) {
      this.mtu = builder.mtu;
    }

    /**
     *
     * @return mtu
     */
    public int getMtu() { return mtu; }

    /**
     *
     * @return mtu
     */
    public long getMtuAsLong() { return mtu & 0xFFFFFFFFL; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(mtu));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV6_PACKET_TOO_BIG_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Packet Too Big Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  MTU: ")
        .append(mtu)
        .append(ls);
      return sb.toString();
    }

  }

}
