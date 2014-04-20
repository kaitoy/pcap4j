/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.io.Serializable;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6Packet extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 1837307843939979665L;

  private static final Logger logger = LoggerFactory.getLogger(IpV6Packet.class);

  private final IpV6Header header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IpV6Packet object.
   */
  public static IpV6Packet newPacket(byte[] rawData) {
    return new IpV6Packet(rawData);
  }

  private IpV6Packet(byte[] rawData) {
    this.header = new IpV6Header(rawData);

    int remainingRawDataLength = rawData.length - header.length();
    int payloadLength;
    if (header.getPayloadLengthAsInt() == 0) {
      logger.debug("Total Length is 0. Assuming segmentation offload to be working.");
      payloadLength = remainingRawDataLength;
    }
    else {
      payloadLength = header.getPayloadLengthAsInt();
    }

    byte[] rawPayload;
    if (payloadLength > remainingRawDataLength) {
      rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            remainingRawDataLength
          );
    }
    else {
      rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
    }

    this.payload
      = PacketFactories.getFactory(Packet.class, IpNumber.class)
          .newInstance(rawPayload, header.getNextHeader());
  }

  private IpV6Packet(Builder builder) {
    if (
         builder == null
      || builder.version == null
      || builder.trafficClass == null
      || builder.flowLabel == null
      || builder.nextHeader == null
      || builder.srcAddr == null
      || builder.dstAddr == null
      || builder.payloadBuilder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.version: ").append(builder.version)
        .append(" builder.trafficClass: ").append(builder.trafficClass)
        .append(" builder.flowLabel: ").append(builder.flowLabel)
        .append(" builder.nextHeader: ").append(builder.nextHeader)
        .append(" builder.srcAddr: ").append(builder.srcAddr)
        .append(" builder.dstAddr: ").append(builder.dstAddr)
        .append(" builder.payloadBuilder: ").append(builder.payloadBuilder);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IpV6Header(builder, payload);
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
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final
  class Builder extends AbstractBuilder implements LengthBuilder<IpV6Packet> {

    private IpVersion version;
    private IpV6TrafficClass trafficClass;
    private IpV6FlowLabel flowLabel;
    private short payloadLength;
    private IpNumber nextHeader;
    private byte hopLimit;
    private Inet6Address srcAddr;
    private Inet6Address dstAddr;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

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
     * @return this Builder object for method chaining.
     */
    public Builder version(IpVersion version) {
      this.version = version;
      return this;
    }

    /**
     *
     * @param trafficClass
     * @return this Builder object for method chaining.
     */
    public Builder trafficClass(IpV6TrafficClass trafficClass) {
      this.trafficClass = trafficClass;
      return this;
    }

    /**
     *
     * @param flowLabel
     * @return this Builder object for method chaining.
     */
    public Builder flowLabel(IpV6FlowLabel flowLabel) {
      this.flowLabel = flowLabel;
      return this;
    }

    /**
     *
     * @param payloadLength
     * @return this Builder object for method chaining.
     */
    public Builder payloadLength(short payloadLength) {
      this.payloadLength = payloadLength;
      return this;
    }

    /**
     *
     * @param nextHeader
     * @return this Builder object for method chaining.
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     *
     * @param hopLimit
     * @return this Builder object for method chaining.
     */
    public Builder hopLimit(byte hopLimit) {
      this.hopLimit = hopLimit;
      return this;
    }

    /**
     *
     * @param srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(Inet6Address srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * @param dstAddr
     * @return this Builder object for method chaining.
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

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
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
  public static final class IpV6Header extends AbstractHeader {

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
    private final IpV6TrafficClass trafficClass;
    private final IpV6FlowLabel flowLabel;
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
        throw new IllegalRawDataException(sb.toString());
      }

      int versionAndTrafficClassAndFlowLabel
        = ByteArrays.getInt(
            rawData,
            VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET
          );

      this.version
        = IpVersion.getInstance(
            (byte)(versionAndTrafficClassAndFlowLabel >>> 28)
          );
      this.trafficClass
        = PacketFactories.getFactory(
            IpV6TrafficClass.class, NA.class
          ).newInstance(
              new byte[] {
                (byte)((versionAndTrafficClassAndFlowLabel & 0x0FF00000) >> 20)
              }
            );
      this.flowLabel
        = PacketFactories.getFactory(
            IpV6FlowLabel.class, NA.class
          ).newInstance(
              ByteArrays.toByteArray(versionAndTrafficClassAndFlowLabel & 0x000FFFFF)
            );
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

    private IpV6Header(Builder builder, Packet payload) {
      this.version = builder.version;
      this.trafficClass = builder.trafficClass;
      this.flowLabel = builder.flowLabel;
      this.nextHeader = builder.nextHeader;
      this.hopLimit = builder.hopLimit;
      this.srcAddr = builder.srcAddr;
      this.dstAddr = builder.dstAddr;

      if (builder.correctLengthAtBuild) {
        if (payload != null) {
          this.payloadLength = (short)(payload.length());
        }
        else {
          this.payloadLength = builder.payloadLength;
        }
      }
      else {
        this.payloadLength = builder.payloadLength;
      }
    }

    /**
     *
     * @return version
     */
    public IpVersion getVersion() {
      return version;
    }

    /**
     *
     * @return trafficClass
     */
    public IpV6TrafficClass getTrafficClass() {
      return trafficClass;
    }

    /**
     *
     * @return flowLabel
     */
    public IpV6FlowLabel getFlowLabel() {
      return flowLabel;
    }

    /**
     *
     * @return payloadLength
     */
    public short getPayloadLength() {
      return payloadLength;
    }

    /**
     *
     * @return payloadLength
     */
    public int getPayloadLengthAsInt() {
      return 0xFFFF & payloadLength;
    }

    /**
     *
     * @return nextHeader
     */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /**
     *
     * @return hopLimit
     */
    public byte getHopLimit() {
      return hopLimit;
    }

    /**
     *
     * @return hopLimit
     */
    public int getHopLimitAsInt() {
      return 0xFF & hopLimit;
    }

    /**
     *
     * @return srcAddr
     */
    public Inet6Address getSrcAddr() {
      return srcAddr;
    }

    /**
     *
     * @return dstAddr
     */
    public Inet6Address getDstAddr() {
      return dstAddr;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(
        ByteArrays.toByteArray(
          version.value() << 28 | trafficClass.value() << 20 | flowLabel.value()
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
        .append(version)
        .append(ls);
      sb.append("  Traffic Class: ")
        .append(trafficClass)
        .append(ls);
      sb.append("  Flow Label: ")
        .append(flowLabel)
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

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6TrafficClass extends Serializable {

    // /* must implement if use PropertiesBasedIpV6TrafficClassFactory */
    // public static IpV6TrafficClass newInstance(byte value);

    /**
     *
     * @return value
     */
    public byte value();

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6FlowLabel extends Serializable {

    // /* must implement if use PropertiesBasedIpV6FlowLabelFactory */
    // public static IpV6FlowLabel newInstance(int value);

    /**
     *
     * @return value
     */
    public int value();

  }

}
