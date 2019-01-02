/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UdpPacket extends AbstractPacket implements TransportPacket {

  /** */
  private static final long serialVersionUID = 4638029542367352625L;

  private final UdpHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UdpPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UdpPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UdpPacket(rawData, offset, length);
  }

  private UdpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new UdpHeader(rawData, offset, length);

    int payloadLength = header.getLengthAsInt() - header.length();
    if (payloadLength < 0) {
      throw new IllegalRawDataException(
          "The value of length field seems to be wrong: " + header.getLengthAsInt());
    }

    if (payloadLength > length - header.length()) {
      payloadLength = length - header.length();
    }

    if (payloadLength != 0) { // payloadLength is positive.
      PacketFactory<Packet, UdpPort> factory =
          PacketFactories.getFactory(Packet.class, UdpPort.class);
      Class<? extends Packet> class4UnknownPort = factory.getTargetClass();
      Class<? extends Packet> class4DstPort = factory.getTargetClass(header.getDstPort());
      UdpPort serverPort;
      if (class4DstPort.equals(class4UnknownPort)) {
        serverPort = header.getSrcPort();
      } else {
        serverPort = header.getDstPort();
      }
      this.payload =
          PacketFactories.getFactory(Packet.class, UdpPort.class)
              .newInstance(rawData, offset + header.length(), payloadLength, serverPort);
    } else {
      this.payload = null;
    }
  }

  private UdpPacket(Builder builder) {
    if (builder == null || builder.srcPort == null || builder.dstPort == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.srcPort: ")
          .append(builder.srcPort)
          .append(" builder.dstPort: ")
          .append(builder.dstPort);
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
      if (!builder.srcAddr.getClass().isInstance(builder.dstAddr)) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ")
            .append(builder.srcAddr)
            .append(" builder.dstAddr: ")
            .append(builder.dstAddr);
        throw new IllegalArgumentException(sb.toString());
      }
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new UdpHeader(builder, payload != null ? payload.getRawData() : new byte[0]);
  }

  @Override
  public UdpHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  /**
   * checksum verification is necessary for IPv6(i.e. acceptZero must be false)
   *
   * @param srcAddr srcAddr
   * @param dstAddr dstAddr
   * @param acceptZero acceptZero
   * @return true if the packet represented by this object has a valid checksum; false otherwise.
   */
  public boolean hasValidChecksum(InetAddress srcAddr, InetAddress dstAddr, boolean acceptZero) {
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

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<UdpPacket>, ChecksumBuilder<UdpPacket> {

    private UdpPort srcPort;
    private UdpPort dstPort;
    private short length;
    private short checksum;
    private Packet.Builder payloadBuilder;
    private InetAddress srcAddr;
    private InetAddress dstAddr;
    private boolean correctLengthAtBuild;
    private boolean correctChecksumAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(UdpPacket packet) {
      this.srcPort = packet.header.srcPort;
      this.dstPort = packet.header.dstPort;
      this.length = packet.header.length;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param srcPort srcPort
     * @return this Builder object for method chaining.
     */
    public Builder srcPort(UdpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     * @param dstPort dstPort
     * @return this Builder object for method chaining.
     */
    public Builder dstPort(UdpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(short length) {
      this.length = length;
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
    public Builder srcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     * used for checksum calculation If the lower-layer packet is a IPv6 packet and the extension
     * headers including a routing header, this parameter is that of the final destination. (i.e.
     * the last element of the Routing header)
     *
     * @param dstAddr dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    @Override
    public UdpPacket build() {
      return new UdpPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class UdpHeader extends AbstractHeader implements TransportHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Src Port            |           Dst Port            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |            Length             |           Checksum            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /*
     *                        IPv4 Pseudo Header
     *
     * 0                               16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       Src IP Address                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       Dst IP Address                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      PAD      | Protocol(UDP) |            Length             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     *                      IPv6 Pseudo Header
     *
     *  0                              16                            31
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
     * |                   Upper-Layer Packet Length                   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                      zero                     |  Next Header  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /** */
    private static final long serialVersionUID = -1746545325551976324L;

    private static final int SRC_PORT_OFFSET = 0;
    private static final int SRC_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int CHECKSUM_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int UCP_HEADER_SIZE = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private static final int IPV4_PSEUDO_HEADER_SIZE = 12;
    private static final int IPV6_PSEUDO_HEADER_SIZE = 40;

    private final UdpPort srcPort;
    private final UdpPort dstPort;
    private final short length;
    private final short checksum;

    private UdpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < UCP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a UDP header(")
            .append(UCP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort = UdpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET + offset));
      this.dstPort = UdpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET + offset));
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET + offset);
    }

    private UdpHeader(Builder builder, byte[] payload) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;

      if (builder.correctLengthAtBuild) {
        this.length = (short) (payload.length + length());
      } else {
        this.length = builder.length;
      }

      if (builder.correctChecksumAtBuild) {
        if ((builder.srcAddr instanceof Inet4Address
                && PacketPropertiesLoader.getInstance().udpV4CalcChecksum())
            || (builder.srcAddr instanceof Inet6Address
                && PacketPropertiesLoader.getInstance().udpV6CalcChecksum())) {
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
        InetAddress srcAddr, InetAddress dstAddr, byte[] header, byte[] payload) {
      byte[] data;
      int destPos;
      int totalLength = payload.length + length();
      boolean lowerLayerIsIpV4 = srcAddr instanceof Inet4Address;

      int pseudoHeaderSize = lowerLayerIsIpV4 ? IPV4_PSEUDO_HEADER_SIZE : IPV6_PSEUDO_HEADER_SIZE;

      if ((totalLength % 2) != 0) {
        data = new byte[totalLength + 1 + pseudoHeaderSize];
        destPos = totalLength + 1;
      } else {
        data = new byte[totalLength + pseudoHeaderSize];
        destPos = totalLength;
      }

      System.arraycopy(header, 0, data, 0, header.length);
      System.arraycopy(payload, 0, data, header.length, payload.length);

      // pseudo header
      System.arraycopy(srcAddr.getAddress(), 0, data, destPos, srcAddr.getAddress().length);
      destPos += srcAddr.getAddress().length;

      System.arraycopy(dstAddr.getAddress(), 0, data, destPos, dstAddr.getAddress().length);
      destPos += dstAddr.getAddress().length;

      if (lowerLayerIsIpV4) {
        // data[destPos] = (byte)0;
        destPos++;
      } else {
        destPos += 3;
      }

      data[destPos] = IpNumber.UDP.value();
      destPos++;

      System.arraycopy(
          ByteArrays.toByteArray((short) totalLength), 0, data, destPos, SHORT_SIZE_IN_BYTES);
      destPos += SHORT_SIZE_IN_BYTES;

      return ByteArrays.calcChecksum(data);
    }

    @Override
    public UdpPort getSrcPort() {
      return srcPort;
    }

    @Override
    public UdpPort getDstPort() {
      return dstPort;
    }

    /** @return length */
    public short getLength() {
      return length;
    }

    /** @return length */
    public int getLengthAsInt() {
      return 0xFFFF & length;
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
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(length));
      rawFields.add(ByteArrays.toByteArray(zeroInsteadOfChecksum ? (short) 0 : checksum));
      return rawFields;
    }

    private byte[] buildRawData(boolean zeroInsteadOfChecksum) {
      return ByteArrays.concatenate(getRawFields(zeroInsteadOfChecksum));
    }

    @Override
    public int length() {
      return UCP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[UDP Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Source port: ").append(getSrcPort()).append(ls);
      sb.append("  Destination port: ").append(getDstPort()).append(ls);
      sb.append("  Length: ").append(getLengthAsInt()).append(" [bytes]").append(ls);
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

      UdpHeader other = (UdpHeader) obj;
      return checksum == other.checksum
          && length == other.length
          && srcPort.equals(other.srcPort)
          && dstPort.equals(other.dstPort);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + srcPort.hashCode();
      result = 31 * result + dstPort.hashCode();
      result = 31 * result + length;
      result = 31 * result + checksum;
      return result;
    }
  }
}
