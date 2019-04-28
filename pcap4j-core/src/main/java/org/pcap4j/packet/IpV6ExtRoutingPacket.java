/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV6RoutingType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6ExtRoutingPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -4408422883412551431L;

  private final IpV6ExtRoutingHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6ExtRoutingPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6ExtRoutingPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6ExtRoutingPacket(rawData, offset, length);
  }

  private IpV6ExtRoutingPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IpV6ExtRoutingHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      PacketFactory<Packet, IpNumber> factory =
          PacketFactories.getFactory(Packet.class, IpNumber.class);
      Class<? extends Packet> nextPacketClass = factory.getTargetClass(header.getNextHeader());
      Packet nextPacket;
      if (nextPacketClass.equals(factory.getTargetClass())) {
        nextPacket =
            PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(
                    rawData,
                    offset + header.length(),
                    payloadLength,
                    NotApplicable.UNKNOWN_IP_V6_EXTENSION);
        if (nextPacket instanceof IllegalPacket) {
          nextPacket = factory.newInstance(rawData, offset + header.length(), payloadLength);
        }
      } else {
        nextPacket =
            factory.newInstance(
                rawData, offset + header.length(), payloadLength, header.getNextHeader());
      }

      this.payload = nextPacket;
    } else {
      this.payload = null;
    }
  }

  private IpV6ExtRoutingPacket(Builder builder) {
    if (builder == null || builder.nextHeader == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextHeader: ")
          .append(builder.nextHeader)
          .append(" builder.data: ")
          .append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IpV6ExtRoutingHeader(builder);
  }

  @Override
  public IpV6ExtRoutingHeader getHeader() {
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
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<IpV6ExtRoutingPacket> {

    private IpNumber nextHeader;
    private byte hdrExtLen;
    private IpV6RoutingType routingType;
    private byte segmentsLeft;
    private IpV6RoutingData data;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(IpV6ExtRoutingPacket packet) {
      this.nextHeader = packet.header.nextHeader;
      this.hdrExtLen = packet.header.hdrExtLen;
      this.routingType = packet.header.routingType;
      this.segmentsLeft = packet.header.segmentsLeft;
      this.data = packet.header.data;
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
     * @param hdrExtLen hdrExtLen
     * @return this Builder object for method chaining.
     */
    public Builder hdrExtLen(byte hdrExtLen) {
      this.hdrExtLen = hdrExtLen;
      return this;
    }

    /**
     * @param routingType routingType
     * @return this Builder object for method chaining.
     */
    public Builder routingType(IpV6RoutingType routingType) {
      this.routingType = routingType;
      return this;
    }

    /**
     * @param segmentsLeft segmentsLeft
     * @return this Builder object for method chaining.
     */
    public Builder segmentsLeft(byte segmentsLeft) {
      this.segmentsLeft = segmentsLeft;
      return this;
    }

    /**
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(IpV6RoutingData data) {
      this.data = data;
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
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6ExtRoutingPacket build() {
      return new IpV6ExtRoutingPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class IpV6ExtRoutingHeader extends AbstractHeader {

    /*
     *   0                              16                            31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                                                               |
     *  .                                                               .
     *  .                       type-specific data                      .
     *  .                                                               .
     *  |                                                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = -72622140516174483L;

    private static final int NEXT_HEADER_OFFSET = 0;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HDR_EXT_LEN_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HDR_EXT_LEN_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int ROUTING_TYPE_OFFSET = HDR_EXT_LEN_OFFSET + HDR_EXT_LEN_SIZE;
    private static final int ROUTING_TYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int SEGMENTS_LEFT_OFFSET = ROUTING_TYPE_OFFSET + ROUTING_TYPE_SIZE;
    private static final int SEGMENTS_LEFT_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int TYPE_SPECIFIC_DATA_OFFSET = SEGMENTS_LEFT_OFFSET + SEGMENTS_LEFT_SIZE;

    private final IpNumber nextHeader;
    private final byte hdrExtLen;
    private final IpV6RoutingType routingType;
    private final byte segmentsLeft;
    private final IpV6RoutingData data;

    private IpV6ExtRoutingHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 4) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data length of IPv6 routing header is must be more than 3. data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.nextHeader =
          IpNumber.getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset));
      this.hdrExtLen = ByteArrays.getByte(rawData, HDR_EXT_LEN_OFFSET + offset);

      int headerLength = (getHdrExtLenAsInt() + 1) * 8;
      if (length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 routing header(")
            .append(headerLength)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.routingType =
          IpV6RoutingType.getInstance(ByteArrays.getByte(rawData, ROUTING_TYPE_OFFSET + offset));
      this.segmentsLeft = ByteArrays.getByte(rawData, SEGMENTS_LEFT_OFFSET + offset);
      this.data =
          PacketFactories.getFactory(IpV6RoutingData.class, IpV6RoutingType.class)
              .newInstance(
                  rawData, TYPE_SPECIFIC_DATA_OFFSET + offset, headerLength - 4, routingType);
    }

    private IpV6ExtRoutingHeader(Builder builder) {
      if (builder.data.length() < 4) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("data length must be more than 3. data: ").append(builder.data);
        throw new IllegalArgumentException(sb.toString());
      }
      if (((builder.data.length() + 4) % 8) != 0) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("(builder.data.length() + 8 ) % 8 must be 0. data: ").append(builder.data);
        throw new IllegalArgumentException(sb.toString());
      }

      this.nextHeader = builder.nextHeader;
      this.routingType = builder.routingType;
      this.segmentsLeft = builder.segmentsLeft;
      this.data = builder.data;

      if (builder.correctLengthAtBuild) {
        this.hdrExtLen = (byte) ((data.length() + 4) / 8 - 1);
      } else {
        this.hdrExtLen = builder.hdrExtLen;
      }
    }

    /** @return nextHeader */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /** @return hdrExtLen */
    public byte getHdrExtLen() {
      return hdrExtLen;
    }

    /** @return hdrExtLen */
    public int getHdrExtLenAsInt() {
      return 0xFF & hdrExtLen;
    }

    /** @return routingType */
    public IpV6RoutingType getRoutingType() {
      return routingType;
    }

    /** @return segmentsLeft */
    public byte getSegmentsLeft() {
      return segmentsLeft;
    }

    /** @return segmentsLeft */
    public int getSegmentsLeftAsInt() {
      return segmentsLeft & 0xFF;
    }

    /** @return data */
    public IpV6RoutingData getData() {
      return data;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hdrExtLen));
      rawFields.add(ByteArrays.toByteArray(routingType.value()));
      rawFields.add(ByteArrays.toByteArray(segmentsLeft));
      rawFields.add(data.getRawData());
      return rawFields;
    }

    @Override
    public int calcLength() {
      return data.length() + 4;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 Routing Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Next Header: ").append(nextHeader).append(ls);
      sb.append("  Hdr Ext Len: ")
          .append(getHdrExtLenAsInt())
          .append(" (")
          .append((getHdrExtLenAsInt() + 1) * 8)
          .append(" [bytes])")
          .append(ls);
      sb.append("  Routing Type: ").append(routingType).append(ls);
      sb.append("  Segments Left: ").append(getSegmentsLeftAsInt()).append(ls);
      sb.append("  type-specific data: ").append(data).append(ls);

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

      IpV6ExtRoutingHeader other = (IpV6ExtRoutingHeader) obj;
      return nextHeader.equals(other.nextHeader)
          && data.equals(other.data)
          && routingType.equals(other.routingType)
          && segmentsLeft == other.segmentsLeft
          && hdrExtLen == other.hdrExtLen;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + nextHeader.hashCode();
      result = 31 * result + hdrExtLen;
      result = 31 * result + routingType.hashCode();
      result = 31 * result + segmentsLeft;
      result = 31 * result + data.hashCode();
      return result;
    }
  }

  /**
   * The interface representing an IPv6 routing data. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV6RoutingData newInstance(byte[] rawData, int offset,
   * int length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6RoutingData extends Serializable {

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
