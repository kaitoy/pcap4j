/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INET6_ADDRESS_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6Packet extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 1837307843939979665L;

  private final IpV6Header header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV6Packet newPacket(byte[] rawData) {
    return new IpV6Packet(rawData);
  }

  private IpV6Packet(byte[] rawData) {
    this.header = new IpV6Header(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          this.header.length(),
          this.header.getPayloadLengthAsInt()
        );

    this.payload
      = PacketFactories.getPacketFactory(IpNumber.class)
          .newPacket(rawPayload, header.getNextHeader());
  }

  private IpV6Packet(Builder builder) {
    if (
         builder == null
      || builder.version == null
      || builder.nextHeader == null
      || builder.srcAddr == null
      || builder.dstAddr == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }

    UdpPacket.Builder udpBuilder = builder.get(UdpPacket.Builder.class);
    if (udpBuilder != null) {
      udpBuilder.dstAddr(builder.dstAddr).srcAddr(builder.srcAddr);
    }
    this.payload = builder.payloadBuilder.build();
    this.header = new IpV6Header(builder, this);
  }

  @Override
  public IpV6Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  protected boolean verify() {
    if (!(payload instanceof UdpPacket)) {
      if (!payload.isValid()) {
        return false;
      }
    }

    UdpPacket udpPacket = payload.get(UdpPacket.class);
    if (udpPacket != null) {
      if (!udpPacket.isValid(header.srcAddr, header.dstAddr)) {
        return false;
      }
    }

    return header.isValid();
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

    private IpVersion version = IpVersion.IP_V6;
    private byte trafficClass = 0;
    private int flowLabel = 0;
    private short payloadLength;
    private IpNumber nextHeader;
    private byte hopLimit;
    private Inet6Address srcAddr;
    private Inet6Address dstAddr;
    private Packet.Builder payloadBuilder;
    private boolean validateAtBuild = true;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    public Builder(IpV6Packet packet) {
      this.version = packet.header.version;
      this.trafficClass = packet.header.trafficClass;
      this.flowLabel = packet.header.flowLabel;
      this.payloadLength = packet.header.payloadLength;
      this.nextHeader = packet.header.nextHeader;
      this.hopLimit = packet.header.hopLimit;
      this.srcAddr = packet.header.srcAddr;
      this.dstAddr = packet.header.dstAddr;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param version
     * @return
     */
    public Builder version(IpVersion version) {
      this.version = version;
      return this;
    }

    /**
     *
     * @param trafficClass
     * @return
     */
    public Builder trafficClass(byte trafficClass) {
      this.trafficClass = trafficClass;
      return this;
    }

    /**
     *
     * @param flowLabel
     * @return
     */
    public Builder flowLabel(int flowLabel) {
      this.flowLabel = flowLabel;
      return this;
    }

    /**
     *
     * @param payloadLength
     * @return
     */
    public Builder payloadLength(short payloadLength) {
      this.payloadLength = payloadLength;
      return this;
    }

    /**
     *
     * @param nextHeader
     * @return
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     *
     * @param hopLimit
     * @return
     */
    public Builder hopLimit(byte hopLimit) {
      this.hopLimit = hopLimit;
      return this;
    }

    /**
     *
     * @param srcAddr
     * @return
     */
    public Builder srcAddr(Inet6Address srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * @param dstAddr
     * @return
     */
    public Builder dstAddr(Inet6Address dstAddr) {
      this.dstAddr = dstAddr;
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

    /**
     *
     * @param validateAtBuild
     * @return
     */
    public Builder validateAtBuild(boolean validateAtBuild) {
      this.validateAtBuild = validateAtBuild;
      return this;
    }

    @Override
    public IpV6Packet build() {
      return new IpV6Packet(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public final class IpV6Header extends AbstractHeader {

    /*
     * 0                               16                              32
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Version| Traffic Class |           Flow Label                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Payload Length        |  Next Header  |   Hop Limit   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                         Source Address                        +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                      Destination Address                      +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /**
     *
     */
    private static final long serialVersionUID = 6587661877529988149L;

    private static final int VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET
      = 0;
    private static final int VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int PAYLOAD_LENGTH_OFFSET
      = VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET
          + VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_SIZE;
    private static final int PAYLOAD_LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int NEXT_HEADER_OFFSET
      = PAYLOAD_LENGTH_OFFSET + PAYLOAD_LENGTH_SIZE;
    private static final int NEXT_HEADER_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int HOP_LIMIT_OFFSET
      = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HOP_LIMIT_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int SRC_ADDR_OFFSET
      = HOP_LIMIT_OFFSET + HOP_LIMIT_SIZE;
    private static final int SRC_ADDR_SIZE
      = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int DST_ADDR_OFFSET
      = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int DST_ADDR_SIZE
      = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int IPV6_HEADER_SIZE
      = DST_ADDR_OFFSET + DST_ADDR_SIZE;

    private final IpVersion version;
    private final byte trafficClass;
    private final int flowLabel;
    private final short payloadLength;
    private final IpNumber nextHeader;
    private final byte hopLimit;
    private final Inet6Address srcAddr;
    private final Inet6Address dstAddr;

    private IpV6Header(byte[] rawData) {
      if (rawData.length < IPV6_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 header(")
          .append(IPV6_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      int versionAndTrafficClassAndFlowLabel
        = ByteArrays.getInt(
            rawData,
            VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET
          );

      this.version
        = IpVersion.getInstance(
            (byte)((versionAndTrafficClassAndFlowLabel & 0xF0000000) >> 28)
          );
      this.trafficClass
        = (byte)((versionAndTrafficClassAndFlowLabel & 0x0FF00000) >> 20);
      this.flowLabel = versionAndTrafficClassAndFlowLabel & 0x000FFFFF;
      this.payloadLength
        = ByteArrays.getShort(rawData, PAYLOAD_LENGTH_OFFSET);
      this.nextHeader
        = IpNumber
            .getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET));
      this.hopLimit
        = ByteArrays.getByte(rawData, HOP_LIMIT_OFFSET);
      this.srcAddr
        = ByteArrays.getInet6Address(rawData, SRC_ADDR_OFFSET);
      this.dstAddr
        = ByteArrays.getInet6Address(rawData, DST_ADDR_OFFSET);
    }

    private IpV6Header(Builder builder, IpV6Packet host) {
      if ((builder.flowLabel & 0xFFF00000) != 0) {
        throw new IllegalArgumentException(
                    "Invalid flowLabel: " + builder.flowLabel
                  );
      }

      this.trafficClass = builder.trafficClass;
      this.flowLabel = builder.flowLabel;
      this.nextHeader = builder.nextHeader;
      this.hopLimit = builder.hopLimit;
      this.srcAddr = builder.srcAddr;
      this.dstAddr = builder.dstAddr;

      if (builder.validateAtBuild) {
        this.version = IpVersion.IP_V6;
        this.payloadLength = (short)(host.payload.length());
      }
      else {
        this.version = builder.version;
        this.payloadLength = builder.payloadLength;
      }
    }

    /**
     *
     * @return
     */
    public IpVersion getVersion() {
      return version;
    }

    /**
     *
     * @return
     */
    public int getVersionAsInt() {
      return 0xFF & version.value();
    }

    /**
     *
     * @return
     */
    public byte getTrafficClass() {
      return trafficClass;
    }

    /**
     *
     * @return
     */
    public int getFlowLabel() {
      return flowLabel;
    }

    /**
     *
     * @return
     */
    public short getPayloadLength() {
      return payloadLength;
    }

    /**
     *
     * @return
     */
    public int getPayloadLengthAsInt() {
      return 0xFFFF & payloadLength;
    }

    /**
     *
     * @return
     */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /**
     *
     * @return
     */
    public byte getHopLimit() {
      return hopLimit;
    }

    /**
     *
     * @return
     */
    public int getHopLimitAsInt() {
      return 0xFF & hopLimit;
    }

    /**
     *
     * @return
     */
    public Inet6Address getSrcAddr() {
      return srcAddr;
    }

    /**
     *
     * @return
     */
    public Inet6Address getDstAddr() {
      return dstAddr;
    }

    @Override
    protected boolean verify() {
      return IpV6Packet.this.payload.length() == getPayloadLengthAsInt();
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(
        ByteArrays.toByteArray(
          version.value() << 28 | trafficClass << 20 | flowLabel
        )
      );
      rawFields.add(ByteArrays.toByteArray(payloadLength));
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hopLimit));
      rawFields.add(ByteArrays.toByteArray(srcAddr));
      rawFields.add(ByteArrays.toByteArray(dstAddr));
      return rawFields;
    }

    @Override
    public int length() {
      return IPV6_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Version: ")
        .append(getVersionAsInt())
        .append(ls);
      sb.append("  Traffic Class: ")
        .append(getTrafficClass())
        .append(ls);
      sb.append("  Flow Label: ")
        .append(getFlowLabel())
        .append(ls);
      sb.append("  Payload length: ")
        .append(getPayloadLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Next Header: ")
        .append(nextHeader)
        .append(ls);
      sb.append("  Hop Limit: ")
        .append(getHopLimitAsInt())
        .append(ls);
      sb.append("  Source address: ")
        .append(srcAddr)
        .append(ls);
      sb.append("  Destination address: ")
        .append(dstAddr)
        .append(ls);

      return sb.toString();
    }

  }

}
