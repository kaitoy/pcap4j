/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
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
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UdpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4638029542367352625L;

  private final UdpHeader header;
  private final Packet payload;

  public static UdpPacket newPacket(byte[] rawData) {
    return new UdpPacket(rawData);
  }

  private UdpPacket(byte[] rawData) {
    this.header = new UdpHeader(rawData);

    int payloadLength = header.getLengthAsInt() - header.length();
    byte[] rawPayload;

    if (payloadLength > rawData.length - header.length()) {
      rawPayload
        = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
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
      = PacketFactories.getFactory(UdpPort.class)
          .newPacket(rawPayload, header.getDstPort());
  }

  private UdpPacket(Builder builder) {
    if (
         builder == null
      || builder.srcPort == null
      || builder.dstPort == null
      || builder.payloadBuilder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.srcPort: ").append(builder.srcPort)
        .append(" builder.dstPort: ").append(builder.dstPort)
        .append(" builder.payloadBuilder: ").append(builder.payloadBuilder);
      throw new NullPointerException(sb.toString());
    }

    if (builder.correctChecksumAtBuild) {
      if (builder.srcAddr == null || builder.dstAddr == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ").append(builder.srcAddr)
          .append(" builder.dstAddr: ").append(builder.dstAddr);
        throw new NullPointerException(sb.toString());
      }
      if (!builder.srcAddr.getClass().isInstance(builder.dstAddr)) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ").append(builder.srcAddr)
          .append(" builder.dstAddr: ").append(builder.dstAddr);
        throw new IllegalArgumentException(sb.toString());
      }
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new UdpHeader(
                    builder,
                    payload.getRawData()
                  );
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
   *
   * checksum varification is necessary for IPv6(i.e. acceptZero must be false)
   *
   * @param srcAddr
   * @param dstAddr
   * @param acceptZero
   * @return
   */
  public boolean hasValidChecksum(
    InetAddress srcAddr, InetAddress dstAddr, boolean acceptZero
  ) {
    if (srcAddr == null || dstAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr)
        .append(" dstAddr: ").append(dstAddr);
      throw new NullPointerException(sb.toString());
    }
    if (!srcAddr.getClass().isInstance(dstAddr)) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr)
        .append(" dstAddr: ").append(dstAddr);
      throw new IllegalArgumentException(sb.toString());
    }

    if (header.checksum == 0) {
      if (acceptZero) { return true; }
      else { return false; }
    }
    return header.calcChecksum(srcAddr, dstAddr, payload.getRawData())
             == header.checksum;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final
  class Builder extends AbstractBuilder
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

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    public Builder(UdpPacket packet) {
      this.srcPort = packet.header.srcPort;
      this.dstPort = packet.header.dstPort;
      this.length = packet.header.length;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param srcPort
     * @return
     */
    public Builder srcPort(UdpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     *
     * @param dstPort
     * @return
     */
    public Builder dstPort(UdpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     *
     * @param length
     * @return
     */
    public Builder length(short length) {
      this.length = length;
      return this;
    }

    /**
     *
     * @param checksum
     * @return
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
     *
     * used for checksum calculation.
     *
     * @param srcAddr
     * @return
     */
    public Builder srcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * used for checksum calculation
     * If the lower-layer packet is a IPv6 packet and
     * the extention headers including a routing header,
     * this parameter is that of the final destination.
     * (i.e. the last element of the Routing header)
     *
     * @param dstAddr
     * @return
     */
    public Builder dstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

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
  public static final class UdpHeader extends AbstractHeader {

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

    /**
     *
     */
    private static final long serialVersionUID = -1746545325551976324L;

    private static final int SRC_PORT_OFFSET
      = 0;
    private static final int SRC_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET
      = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET
      = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET
      = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int UCP_HEADER_SIZE
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private static final int IP_V4_PSEUDO_HEADER_SIZE = 12;
    private static final int IP_V6_PSEUDO_HEADER_SIZE = 40;

    private final UdpPort srcPort;
    private final UdpPort dstPort;
    private final short length;
    private final short checksum;

    private UdpHeader(byte[] rawData) {
      if (rawData.length < UCP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a UDP header(")
          .append(UCP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort
        = UdpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET));
      this.dstPort
        = UdpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET));
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
    }

    private UdpHeader(Builder builder, byte[] payload) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;

      if (builder.correctLengthAtBuild) {
        this.length = (short)(payload.length + length());
      }
      else {
        this.length = builder.length;
      }

      if (builder.correctChecksumAtBuild) {
        if (
          (
            builder.srcAddr instanceof Inet4Address
              && PacketPropertiesLoader.getInstance().udpV4CalcChecksum()
          )
          ||
          (
            builder.srcAddr instanceof Inet6Address
              && PacketPropertiesLoader.getInstance().udpV6CalcChecksum()
          )
        ) {
          this.checksum = calcChecksum(builder.srcAddr, builder.dstAddr, payload);
        }
        else {
          this.checksum = (short)0;
        }
      }
      else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(
      InetAddress srcAddr, InetAddress dstAddr, byte[] payload
    ) {
      byte[] data;
      int destPos;
      int totalLength = payload.length + length();
      boolean lowerLayerIsIpV4 = srcAddr instanceof Inet4Address;

      int pseudoHeaderSize
        = lowerLayerIsIpV4 ? IP_V4_PSEUDO_HEADER_SIZE
                           : IP_V6_PSEUDO_HEADER_SIZE;

      if ((totalLength % 2) != 0) {
        data = new byte[totalLength + 1 + pseudoHeaderSize];
        destPos = totalLength + 1;
      }
      else {
        data = new byte[totalLength + pseudoHeaderSize];
        destPos = totalLength;
      }

      // getRawData()だとchecksum field設定前にrawDataがキャッシュされてしまう場合があるので、
      // 代わりにbuildRawData()を使う。
      System.arraycopy(buildRawData(), 0, data, 0, length());
      System.arraycopy(payload, 0, data, length(), payload.length);

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      // pseudo header
      System.arraycopy(
        srcAddr.getAddress(), 0,
        data, destPos, srcAddr.getAddress().length
      );
      destPos += srcAddr.getAddress().length;

      System.arraycopy(
        dstAddr.getAddress(), 0,
        data, destPos, dstAddr.getAddress().length
      );
      destPos += dstAddr.getAddress().length;

      if (lowerLayerIsIpV4) {
        //data[destPos] = (byte)0;
        destPos++;
      }
      else {
        destPos += 3;
      }

      data[destPos] = IpNumber.UDP.value();
      destPos++;

      System.arraycopy(
        ByteArrays.toByteArray((short)totalLength), 0,
        data, destPos, SHORT_SIZE_IN_BYTES
      );
      destPos += SHORT_SIZE_IN_BYTES;

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return
     */
    public UdpPort getSrcPort() {
      return srcPort;
    }

    /**
     *
     * @return
     */
    public UdpPort getDstPort() {
      return dstPort;
    }

    /**
     *
     * @return
     */
    public short getLength() {
      return length;
    }

    /**
     *
     * @return
     */
    public int getLengthAsInt() {
      return (int)(0xFFFF & length);
    }

    /**
     *
     * @return
     */
    public short getChecksum() {
      return checksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(length));
      rawFields.add(ByteArrays.toByteArray(checksum));
      return rawFields;
    }

    @Override
    public int length() {
      return UCP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[UDP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Source port: ")
        .append(getSrcPort())
        .append(ls);
      sb.append("  Destination port: ")
        .append(getDstPort())
        .append(ls);
      sb.append("  Length: ")
        .append(getLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append(ls);

      return sb.toString();
    }

  }

}
