/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6ExtFragmentPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 8789423734186381406L;

  private final IpV6ExtFragmentHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6ExtFragmentPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6ExtFragmentPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6ExtFragmentPacket(rawData, offset, length);
  }

  private IpV6ExtFragmentPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IpV6ExtFragmentHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, NotApplicable.class)
              .newInstance(
                  rawData, offset + header.length(), payloadLength, NotApplicable.FRAGMENTED);
    } else {
      this.payload = null;
    }
  }

  private IpV6ExtFragmentPacket(Builder builder) {
    if (builder == null || builder.nextHeader == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextHeader: ")
          .append(builder.nextHeader);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IpV6ExtFragmentHeader(builder);
  }

  @Override
  public IpV6ExtFragmentHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class Builder extends AbstractBuilder {

    private IpNumber nextHeader;
    private byte reserved;
    private short fragmentOffset;
    private byte res;
    private boolean m;
    private int identification;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(IpV6ExtFragmentPacket packet) {
      this.nextHeader = packet.header.nextHeader;
      this.reserved = packet.header.reserved;
      this.fragmentOffset = packet.header.fragmentOffset;
      this.res = packet.header.res;
      this.m = packet.header.m;
      this.identification = packet.header.identification;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param nextHeader nextHeader
     * @return this Builder object for method chaining.
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param fragmentOffset fragmentOffset
     * @return this Builder object for method chaining.
     */
    public Builder fragmentOffset(short fragmentOffset) {
      this.fragmentOffset = fragmentOffset;
      return this;
    }

    /**
     * @param res res
     * @return this Builder object for method chaining.
     */
    public Builder res(byte res) {
      this.res = res;
      return this;
    }

    /**
     * @param m m
     * @return this Builder object for method chaining.
     */
    public Builder m(boolean m) {
      this.m = m;
      return this;
    }

    /**
     * @param identification identification
     * @return this Builder object for method chaining.
     */
    public Builder identification(int identification) {
      this.identification = identification;
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    @Override
    public Packet.Builder getPayloadBuilder() {
      return payloadBuilder;
    }

    @Override
    public IpV6ExtFragmentPacket build() {
      return new IpV6ExtFragmentPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class IpV6ExtFragmentHeader extends AbstractHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                         Identification                        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /** */
    private static final long serialVersionUID = 3488980383672562461L;

    private static final int NEXT_HEADER_OFFSET = 0;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int RESERVED_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int RESERVED_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int FRAGMENT_OFFSET_AND_RES_AND_M_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
    private static final int FFRAGMENT_OFFSET_AND_RES_AND_M_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int IDENTIFICATION_OFFSET =
        FRAGMENT_OFFSET_AND_RES_AND_M_OFFSET + FFRAGMENT_OFFSET_AND_RES_AND_M_SIZE;
    private static final int IDENTIFICATION_SIZE = INT_SIZE_IN_BYTES;
    private static final int IPV6_EXT_FRAGMENT_HEADER_SIZE =
        IDENTIFICATION_OFFSET + IDENTIFICATION_SIZE;

    private final IpNumber nextHeader;
    private final byte reserved;
    private final short fragmentOffset;
    private final byte res;
    private final boolean m;
    private final int identification;

    private IpV6ExtFragmentHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < IPV6_EXT_FRAGMENT_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 fragment header(")
            .append(IPV6_EXT_FRAGMENT_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.nextHeader =
          IpNumber.getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset));
      this.reserved = ByteArrays.getByte(rawData, RESERVED_OFFSET + offset);
      short fragmentOffsetAndResAndM =
          ByteArrays.getShort(rawData, FRAGMENT_OFFSET_AND_RES_AND_M_OFFSET + offset);
      this.fragmentOffset = (short) ((fragmentOffsetAndResAndM & 0xFFF8) >> 3);
      this.res = (byte) ((fragmentOffsetAndResAndM & 0x0006) >> 1);
      this.m = (fragmentOffsetAndResAndM & 0x0001) == 1;
      this.identification = ByteArrays.getInt(rawData, IDENTIFICATION_OFFSET + offset);
    }

    private IpV6ExtFragmentHeader(Builder builder) {
      if ((builder.fragmentOffset & 0xE000) != 0) {
        throw new IllegalArgumentException("Invalid fragmentOffset: " + builder.fragmentOffset);
      }
      if ((builder.res & 0xFFFC) != 0) {
        throw new IllegalArgumentException("Invalid res: " + builder.res);
      }

      this.nextHeader = builder.nextHeader;
      this.reserved = builder.reserved;
      this.fragmentOffset = builder.fragmentOffset;
      this.res = builder.res;
      this.m = builder.m;
      this.identification = builder.identification;
    }

    /** @return nextHeader */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /** @return reserved */
    public byte getReserved() {
      return reserved;
    }

    /** @return fragmentOffset */
    public short getFragmentOffset() {
      return fragmentOffset;
    }

    /** @return res */
    public byte getRes() {
      return res;
    }

    /** @return m */
    public boolean getM() {
      return m;
    }

    /** @return identification */
    public int getIdentification() {
      return identification;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(reserved));
      rawFields.add(
          ByteArrays.toByteArray((short) ((fragmentOffset << 3) | (res << 1) | (m ? 1 : 0))));
      rawFields.add(ByteArrays.toByteArray(identification));
      return rawFields;
    }

    @Override
    public int length() {
      return IPV6_EXT_FRAGMENT_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 Fragment Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Next Header: ").append(nextHeader).append(ls);
      sb.append("  Reserved: ").append(ByteArrays.toHexString(reserved, " ")).append(ls);
      sb.append("  Fragment Offset: ").append(fragmentOffset).append(ls);
      sb.append("  Res: ").append(ByteArrays.toHexString(res, " ")).append(ls);
      sb.append("  M: ").append(m).append(ls);
      sb.append("  Identification: ").append(identification).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      IpV6ExtFragmentHeader other = (IpV6ExtFragmentHeader) obj;
      return fragmentOffset == other.fragmentOffset
          && identification == other.identification
          && nextHeader.equals(other.nextHeader)
          && m == other.m
          && reserved == other.reserved
          && res == other.res;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + nextHeader.hashCode();
      result = 31 * result + reserved;
      result = 31 * result + fragmentOffset;
      result = 31 * result + res;
      result = 31 * result + (m ? 1231 : 1237);
      result = 31 * result + identification;
      return result;
    }
  }
}
