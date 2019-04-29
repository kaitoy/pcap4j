/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6CommonPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 7643067752830062365L;

  private final IcmpV6CommonHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV6CommonPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV6CommonPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV6CommonPacket(rawData, offset, length);
  }

  private IcmpV6CommonPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV6CommonHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, IcmpV6Type.class)
              .newInstance(rawData, offset + header.length(), payloadLength, header.getType());
    } else {
      this.payload = null;
    }
  }

  private IcmpV6CommonPacket(Builder builder) {
    if (builder == null || builder.type == null || builder.code == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.type: ")
          .append(builder.type)
          .append(" builder.code: ")
          .append(builder.code);
      throw new NullPointerException(sb.toString());
    }

    if (builder.correctChecksumAtBuild) {
      if (builder.srcAddr == null || builder.dstAddr == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ")
            .append(builder.srcAddr)
            .append(" builder.dstAddr: ")
            .append(builder.dstAddr);
        throw new NullPointerException(sb.toString());
      }
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IcmpV6CommonHeader(builder, payload.getRawData());
  }

  @Override
  public IcmpV6CommonHeader getHeader() {
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
   * @param srcAddr srcAddr
   * @param dstAddr dstAddr
   * @param acceptZero acceptZero
   * @return true if the packet represented by this object has a valid checksum; false otherwise.
   */
  public boolean hasValidChecksum(Inet6Address srcAddr, Inet6Address dstAddr, boolean acceptZero) {
    if (srcAddr == null || dstAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr).append(" dstAddr: ").append(dstAddr);
      throw new NullPointerException(sb.toString());
    }
    if (!srcAddr.getClass().isInstance(dstAddr)) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr).append(" dstAddr: ").append(dstAddr);
      throw new IllegalArgumentException(sb.toString());
    }

    byte[] payloadData = payload != null ? payload.getRawData() : new byte[0];
    short calculatedChecksum =
        header.calcChecksum(srcAddr, dstAddr, header.getRawData(), payloadData);
    if (calculatedChecksum == 0) {
      return true;
    }

    if (header.checksum == 0 && acceptZero) {
      return true;
    }

    return false;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder extends AbstractBuilder
      implements ChecksumBuilder<IcmpV6CommonPacket> {

    private IcmpV6Type type;
    private IcmpV6Code code;
    private short checksum;
    private Packet.Builder payloadBuilder;
    private Inet6Address srcAddr;
    private Inet6Address dstAddr;
    private boolean correctChecksumAtBuild;

    /** */
    public Builder() {}

    private Builder(IcmpV6CommonPacket packet) {
      this.type = packet.header.type;
      this.code = packet.header.code;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(IcmpV6Type type) {
      this.type = type;
      return this;
    }

    /**
     * @param code code
     * @return this Builder object for method chaining.
     */
    public Builder code(IcmpV6Code code) {
      this.code = code;
      return this;
    }

    /**
     * @param checksum checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(short checksum) {
      this.checksum = checksum;
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
     * used for checksum calculation.
     *
     * @param srcAddr srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(Inet6Address srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     * used for checksum calculation.
     *
     * @param dstAddr dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(Inet6Address dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    @Override
    public IcmpV6CommonPacket build() {
      return new IcmpV6CommonPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class IcmpV6CommonHeader extends AbstractHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      Type     |     Code      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Checksum              |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = -7473322861606186L;

    private static final int TYPE_OFFSET = 0;
    private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CODE_OFFSET = TYPE_OFFSET + TYPE_SIZE;
    private static final int CODE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET = CODE_OFFSET + CODE_SIZE;
    private static final int CHECKSUM_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ICMPV6_COMMON_HEADER_SIZE = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private static final int ICMPV6_PSEUDO_HEADER_SIZE = 40;

    private final IcmpV6Type type;
    private final IcmpV6Code code;
    private final short checksum;

    private IcmpV6CommonHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < ICMPV6_COMMON_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv6 common header(")
            .append(ICMPV6_COMMON_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.type = IcmpV6Type.getInstance(ByteArrays.getByte(rawData, TYPE_OFFSET + offset));
      this.code =
          IcmpV6Code.getInstance(type.value(), ByteArrays.getByte(rawData, CODE_OFFSET + offset));
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET + offset);
    }

    private IcmpV6CommonHeader(Builder builder, byte[] payload) {
      this.type = builder.type;
      this.code = builder.code;

      if (builder.correctChecksumAtBuild) {
        if (PacketPropertiesLoader.getInstance().icmpV6CalcChecksum()) {
          this.checksum =
              calcChecksum(builder.srcAddr, builder.dstAddr, buildRawData(true), payload);
        } else {
          this.checksum = (short) 0;
        }
      } else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(
        Inet6Address srcAddr, Inet6Address dstAddr, byte[] header, byte[] payload) {
      byte[] data;
      int destPos;
      int totalLength = payload.length + length();

      if ((totalLength % 2) != 0) {
        data = new byte[totalLength + 1 + ICMPV6_PSEUDO_HEADER_SIZE];
        destPos = totalLength + 1;
      } else {
        data = new byte[totalLength + ICMPV6_PSEUDO_HEADER_SIZE];
        destPos = totalLength;
      }

      System.arraycopy(header, 0, data, 0, header.length);
      System.arraycopy(payload, 0, data, header.length, payload.length);

      // pseudo header
      System.arraycopy(srcAddr.getAddress(), 0, data, destPos, srcAddr.getAddress().length);
      destPos += srcAddr.getAddress().length;

      System.arraycopy(dstAddr.getAddress(), 0, data, destPos, dstAddr.getAddress().length);
      destPos += dstAddr.getAddress().length;

      destPos += 3;

      data[destPos] = IpNumber.ICMPV6.value();
      destPos++;

      System.arraycopy(
          ByteArrays.toByteArray((short) totalLength), 0, data, destPos, SHORT_SIZE_IN_BYTES);
      destPos += SHORT_SIZE_IN_BYTES;

      return ByteArrays.calcChecksum(data);
    }

    /** @return type */
    public IcmpV6Type getType() {
      return type;
    }

    /** @return code */
    public IcmpV6Code getCode() {
      return code;
    }

    /** @return checksum */
    public short getChecksum() {
      return checksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      return getRawFields(false);
    }

    private List<byte[]> getRawFields(boolean zeroInsteadOfChecksum) {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(type.value()));
      rawFields.add(ByteArrays.toByteArray(code.value()));
      rawFields.add(ByteArrays.toByteArray(zeroInsteadOfChecksum ? (short) 0 : checksum));
      return rawFields;
    }

    private byte[] buildRawData(boolean zeroInsteadOfChecksum) {
      return ByteArrays.concatenate(getRawFields(zeroInsteadOfChecksum));
    }

    @Override
    public int length() {
      return ICMPV6_COMMON_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Common Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Type: ").append(type).append(ls);
      sb.append("  Code: ").append(code).append(ls);
      sb.append("  Checksum: 0x").append(ByteArrays.toHexString(checksum, "")).append(ls);

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

      IcmpV6CommonHeader other = (IcmpV6CommonHeader) obj;
      return checksum == other.checksum && type.equals(other.type) && code.equals(other.code);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + type.hashCode();
      result = 31 * result + code.hashCode();
      result = 31 * result + checksum;
      return result;
    }
  }

  /**
   * The interface representing an IPv6 neighbor discovery option. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV6NeighborDiscoveryOption newInstance(byte[] rawData,
   * int offset, int length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public interface IpV6NeighborDiscoveryOption extends Serializable {

    /** @return type */
    public IpV6NeighborDiscoveryOptionType getType();

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
