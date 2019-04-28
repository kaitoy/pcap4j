/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INET6_ADDRESS_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6Packet extends AbstractPacket implements IpPacket {

  /** */
  private static final long serialVersionUID = 1837307843939979665L;

  private static final Logger logger = LoggerFactory.getLogger(IpV6Packet.class);

  private final IpV6Header header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6Packet object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6Packet(rawData, offset, length);
  }

  private IpV6Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new IpV6Header(rawData, offset, length);

    int remainingRawDataLength = length - header.length();
    int payloadLength;
    if (header.getPayloadLengthAsInt() == 0) {
      logger.debug("Total Length is 0. Assuming segmentation offload to be working.");
      payloadLength = remainingRawDataLength;
    } else {
      payloadLength = header.getPayloadLengthAsInt();
      if (payloadLength < 0) {
        throw new IllegalRawDataException(
            "The value of payload length field seems to be wrong: "
                + header.getPayloadLengthAsInt());
      }

      if (payloadLength > remainingRawDataLength) {
        payloadLength = remainingRawDataLength;
      }
    }

    if (payloadLength != 0) { // payloadLength is positive.
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

  private IpV6Packet(Builder builder) {
    if (builder == null
        || builder.version == null
        || builder.trafficClass == null
        || builder.flowLabel == null
        || builder.nextHeader == null
        || builder.srcAddr == null
        || builder.dstAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.version: ")
          .append(builder.version)
          .append(" builder.trafficClass: ")
          .append(builder.trafficClass)
          .append(" builder.flowLabel: ")
          .append(builder.flowLabel)
          .append(" builder.nextHeader: ")
          .append(builder.nextHeader)
          .append(" builder.srcAddr: ")
          .append(builder.srcAddr)
          .append(" builder.dstAddr: ")
          .append(builder.dstAddr);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
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
  public static final class Builder extends AbstractBuilder implements LengthBuilder<IpV6Packet> {

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

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(IpV6Packet packet) {
      this.version = packet.header.version;
      this.trafficClass = packet.header.trafficClass;
      this.flowLabel = packet.header.flowLabel;
      this.payloadLength = packet.header.payloadLength;
      this.nextHeader = packet.header.nextHeader;
      this.hopLimit = packet.header.hopLimit;
      this.srcAddr = packet.header.srcAddr;
      this.dstAddr = packet.header.dstAddr;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param version version
     * @return this Builder object for method chaining.
     */
    public Builder version(IpVersion version) {
      this.version = version;
      return this;
    }

    /**
     * @param trafficClass trafficClass
     * @return this Builder object for method chaining.
     */
    public Builder trafficClass(IpV6TrafficClass trafficClass) {
      this.trafficClass = trafficClass;
      return this;
    }

    /**
     * @param flowLabel flowLabel
     * @return this Builder object for method chaining.
     */
    public Builder flowLabel(IpV6FlowLabel flowLabel) {
      this.flowLabel = flowLabel;
      return this;
    }

    /**
     * @param payloadLength payloadLength
     * @return this Builder object for method chaining.
     */
    public Builder payloadLength(short payloadLength) {
      this.payloadLength = payloadLength;
      return this;
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
     * @param hopLimit hopLimit
     * @return this Builder object for method chaining.
     */
    public Builder hopLimit(byte hopLimit) {
      this.hopLimit = hopLimit;
      return this;
    }

    /**
     * @param srcAddr srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(Inet6Address srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     * @param dstAddr dstAddr
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

    @Override
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
  public static final class IpV6Header extends AbstractHeader implements IpHeader {

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

    /** */
    private static final long serialVersionUID = 6587661877529988149L;

    private static final int VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET = 0;
    private static final int VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_SIZE = INT_SIZE_IN_BYTES;
    private static final int PAYLOAD_LENGTH_OFFSET =
        VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET
            + VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_SIZE;
    private static final int PAYLOAD_LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int NEXT_HEADER_OFFSET = PAYLOAD_LENGTH_OFFSET + PAYLOAD_LENGTH_SIZE;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HOP_LIMIT_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HOP_LIMIT_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int SRC_ADDR_OFFSET = HOP_LIMIT_OFFSET + HOP_LIMIT_SIZE;
    private static final int SRC_ADDR_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int DST_ADDR_OFFSET = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int DST_ADDR_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
    private static final int IPV6_HEADER_SIZE = DST_ADDR_OFFSET + DST_ADDR_SIZE;

    private final IpVersion version;
    private final IpV6TrafficClass trafficClass;
    private final IpV6FlowLabel flowLabel;
    private final short payloadLength;
    private final IpNumber nextHeader;
    private final byte hopLimit;
    private final Inet6Address srcAddr;
    private final Inet6Address dstAddr;

    private IpV6Header(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < IPV6_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 header(")
            .append(IPV6_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int versionAndTrafficClassAndFlowLabel =
          ByteArrays.getInt(rawData, VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET + offset);

      this.version = IpVersion.getInstance((byte) (versionAndTrafficClassAndFlowLabel >>> 28));
      this.trafficClass =
          PacketFactories.getFactory(IpV6TrafficClass.class, NotApplicable.class)
              .newInstance(
                  new byte[] {(byte) ((versionAndTrafficClassAndFlowLabel & 0x0FF00000) >> 20)},
                  0,
                  1);
      this.flowLabel =
          PacketFactories.getFactory(IpV6FlowLabel.class, NotApplicable.class)
              .newInstance(rawData, VERSION_AND_TRAFFIC_CLASS_AND_FLOW_LABEL_OFFSET + offset, 4);
      this.payloadLength = ByteArrays.getShort(rawData, PAYLOAD_LENGTH_OFFSET + offset);
      this.nextHeader =
          IpNumber.getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset));
      this.hopLimit = ByteArrays.getByte(rawData, HOP_LIMIT_OFFSET + offset);
      this.srcAddr = ByteArrays.getInet6Address(rawData, SRC_ADDR_OFFSET + offset);
      this.dstAddr = ByteArrays.getInet6Address(rawData, DST_ADDR_OFFSET + offset);
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
          this.payloadLength = (short) (payload.length());
        } else {
          this.payloadLength = builder.payloadLength;
        }
      } else {
        this.payloadLength = builder.payloadLength;
      }
    }

    @Override
    public IpVersion getVersion() {
      return version;
    }

    /** @return trafficClass */
    public IpV6TrafficClass getTrafficClass() {
      return trafficClass;
    }

    /** @return flowLabel */
    public IpV6FlowLabel getFlowLabel() {
      return flowLabel;
    }

    /** @return payloadLength */
    public short getPayloadLength() {
      return payloadLength;
    }

    /** @return payloadLength */
    public int getPayloadLengthAsInt() {
      return 0xFFFF & payloadLength;
    }

    /** @return nextHeader */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    @Override
    public IpNumber getProtocol() {
      return nextHeader;
    }

    /** @return hopLimit */
    public byte getHopLimit() {
      return hopLimit;
    }

    /** @return hopLimit */
    public int getHopLimitAsInt() {
      return 0xFF & hopLimit;
    }

    @Override
    public Inet6Address getSrcAddr() {
      return srcAddr;
    }

    @Override
    public Inet6Address getDstAddr() {
      return dstAddr;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(
          ByteArrays.toByteArray(
              version.value() << 28 | (0xFF & trafficClass.value()) << 20 | flowLabel.value()));
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

      sb.append("[IPv6 Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Version: ").append(version).append(ls);
      sb.append("  Traffic Class: ").append(trafficClass).append(ls);
      sb.append("  Flow Label: ").append(flowLabel).append(ls);
      sb.append("  Payload length: ").append(getPayloadLengthAsInt()).append(" [bytes]").append(ls);
      sb.append("  Next Header: ").append(nextHeader).append(ls);
      sb.append("  Hop Limit: ").append(getHopLimitAsInt()).append(ls);
      sb.append("  Source address: ").append(srcAddr).append(ls);
      sb.append("  Destination address: ").append(dstAddr).append(ls);

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

      IpV6Header other = (IpV6Header) obj;
      return srcAddr.equals(other.srcAddr)
          && dstAddr.equals(other.dstAddr)
          && payloadLength == other.payloadLength
          && hopLimit == other.hopLimit
          && nextHeader.equals(other.nextHeader)
          && trafficClass.equals(other.trafficClass)
          && flowLabel.equals(other.flowLabel)
          && version.equals(other.version);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + version.hashCode();
      result = 31 * result + trafficClass.hashCode();
      result = 31 * result + flowLabel.hashCode();
      result = 31 * result + payloadLength;
      result = 31 * result + nextHeader.hashCode();
      result = 31 * result + hopLimit;
      result = 31 * result + srcAddr.hashCode();
      result = 31 * result + dstAddr.hashCode();
      return result;
    }
  }

  /**
   * The interface representing an IPv6 traffic class. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV6TrafficClass newInstance(byte value)}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6TrafficClass extends Serializable {

    /** @return value */
    public byte value();
  }

  /**
   * The interface representing an IPv6 flow label. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV6FlowLabel newInstance(int value)}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6FlowLabel extends Serializable {

    /** @return value */
    public int value();
  }
}
