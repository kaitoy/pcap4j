/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
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
    this.header = new UdpHeader(rawData, this);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          this.header.length(),
          this.header.getLengthAsInt() - this.header.length()
        );

    this.payload
      = PacketFactories.getPacketFactory(UdpPort.class)
          .newPacket(rawPayload, header.getDstPort());
  }

  private UdpPacket(Builder builder) {
    if (
         builder == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }

    if (
         builder.validateAtBuild
      && (builder.srcAddr == null || builder.dstAddr == null)
    ) {
      throw new NullPointerException();
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new UdpHeader(builder, this);
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
   */
  @Deprecated
  @Override
  public boolean verify() {
    return false;
  }

  /**
   *
   */
  @Deprecated
  @Override
  public boolean isValid() {
    return false;
  }

  /**
   * Because the result of this method depends on srcAddr and dstAddr
   * it will not be cached.
   *
   * @param srcAddr
   * @param dstAddr
   * @return
   */
  public boolean isValid(InetAddress srcAddr, InetAddress dstAddr) {
    if (!payload.isValid()) {
      return false;
    }
    return header.isValid(srcAddr, dstAddr);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private UdpPort srcPort;
    private UdpPort dstPort;
    private short length;
    private short checksum;
    private Packet.Builder payloadBuilder;
    private InetAddress srcAddr;
    private InetAddress dstAddr;
    private boolean validateAtBuild = true;

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
     * @param srcAddr
     * @return
     */
    public Builder srcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * @param dstAddr
     * @return
     */
    public Builder dstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
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
    public UdpPacket build() {
      return new UdpPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public final class UdpHeader extends AbstractHeader {

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

    private static final int PSEUDO_HEADER_SIZE = 12;

    private final UdpPort srcPort;
    private final UdpPort dstPort;
    private final short length;
    private final short checksum;

    private UdpHeader(byte[] rawData, UdpPacket host) {
      if (rawData.length < UCP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a UDP header(")
          .append(UCP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.srcPort
        = UdpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET));
      this.dstPort
        = UdpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET));
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
    }

    private UdpHeader(Builder builder, UdpPacket host) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;

      if (builder.validateAtBuild) {
        this.length = (short)(host.payload.length() + length());

        if (
          PacketPropertiesLoader.getInstance()
            .isEnabledUdpChecksumVaridation()
        ) {
          this.checksum = calcChecksum(builder.srcAddr, builder.dstAddr);
        }
        else {
          this.checksum = (short)0;
        }
      }
      else {
        this.length = builder.length;
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(InetAddress srcAddr, InetAddress dstAddr) {
      byte[] data;
      int destPos;

      if ((length % 2) != 0) {
        data = new byte[length + 1 + PSEUDO_HEADER_SIZE];
        destPos = length + 1;
      }
      else {
        data = new byte[length + PSEUDO_HEADER_SIZE];
        destPos = length;
      }

      System.arraycopy(buildRawData(), 0, data, 0, length());
      System.arraycopy(
        UdpPacket.this.payload.getRawData(), 0,
        data, length(), UdpPacket.this.payload.length()
      );

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      // pseudo header
      System.arraycopy(
        srcAddr.getAddress(), 0,
        data, destPos, ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES
      );
      destPos += ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;

      System.arraycopy(
        dstAddr.getAddress(), 0,
        data, destPos, ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES
      );
      destPos += ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;

      data[destPos] = (byte)0;
      destPos++;

      data[destPos] = IpNumber.UDP.value();
      destPos++;

      System.arraycopy(
        ByteArrays.toByteArray(length), 0,
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

    /**
     *
     */
    @Deprecated
    @Override
    protected boolean verify() {
      return false;
    }

    /**
     *
     */
    @Deprecated
    @Override
    public boolean isValid() {
      return false;
    }

    /**
     * Because the result of this method depends on srcAddr and dstAddr
     * it will not be cached.
     *
     * @param srcAddr
     * @param dstAddr
     * @return
     */
    public boolean isValid(InetAddress srcAddr, InetAddress dstAddr) {
      if (
        PacketPropertiesLoader.getInstance()
          .isEnabledUdpChecksumVerification()
      ) {
        short cs = getChecksum();
        return    ((short)UdpPacket.this.length() != length())
               && (cs == 0 ? true : calcChecksum(srcAddr, dstAddr) != cs);
      }
      else {
        return true;
      }
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
