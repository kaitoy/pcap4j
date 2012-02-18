/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namedvalue.IpNumber;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.ValueCache;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UdpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4638029542367352625L;

  private static final int PSEUDO_HEADER_SIZE = 12;

  private final UdpHeader header;
  private final Packet payload;

  private final ValueCache<Boolean> validCache = new ValueCache<Boolean>();

  public static UdpPacket newPacket(byte[] rawData) {
    return new UdpPacket(rawData);
  }

  private UdpPacket(byte[] rawData) {
    this.header = new UdpHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          this.header.length(),
          rawData.length - this.header.length()
        );

    this.payload
      = PacketFactory.newPacketByPort(rawPayload, header.getDstPort());
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
    this.header = new UdpHeader(builder);
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
    throw new UnsupportedOperationException();
  }

  /**
   *
   */
  @Deprecated
  @Override
  public boolean isValid() {
    throw new UnsupportedOperationException();
  }

  /**
   *
   * @param srcAddr
   * @param dstAddr
   * @return
   */
  private boolean verify(InetAddress srcAddr, InetAddress dstAddr) {
    if (!payload.isValid()) {
      return false;
    }
    return header.isValid(srcAddr, dstAddr);
  }

  /**
   *
   * @param srcAddr
   * @param dstAddr
   * @return
   */
  public boolean isValid(InetAddress srcAddr, InetAddress dstAddr) {
    Boolean result = validCache.getValue();
    if (result == null) {
      synchronized (validCache) {
        result = validCache.getValue();
        if (result == null) {
          result = verify(srcAddr, dstAddr);
          validCache.setValue(result);
        }
      }
    }
    return result.booleanValue();
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder implements Packet.Builder {

    private short srcPort;
    private short dstPort;
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
    public Builder srcPort(short srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     *
     * @param dstPort
     * @return
     */
    public Builder dstPort(short dstPort) {
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

    /**
     *
     * @param payloadBuilder
     * @return
     */
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
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
      = SHORT_SIZE_IN_BYTE;
    private static final int DST_PORT_OFFSET
      = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int LENGTH_OFFSET
      = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int LENGTH_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int CHECKSUM_OFFSET
      = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int UCP_HEADER_SIZE
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private final short srcPort;
    private final short dstPort;
    private final short length;
    private final short checksum;

    private final ValueCache<Boolean> validCache = new ValueCache<Boolean>();

    private UdpHeader(byte[] rawData) {
      if (rawData.length < UCP_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.srcPort = ByteArrays.getShort(rawData, SRC_PORT_OFFSET);
      this.dstPort = ByteArrays.getShort(rawData, DST_PORT_OFFSET);
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
    }

    private UdpHeader(Builder builder) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;

      if (builder.validateAtBuild) {
        this.length = (short)(UdpPacket.this.payload.length() + length());

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
        data, destPos, ByteArrays.IP_ADDRESS_SIZE_IN_BYTE
      );
      destPos += ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;

      System.arraycopy(
        dstAddr.getAddress(), 0,
        data, destPos, ByteArrays.IP_ADDRESS_SIZE_IN_BYTE
      );
      destPos += ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;

      data[destPos] = (byte)0;
      destPos++;

      data[destPos] = IpNumber.UDP.value();
      destPos++;

      System.arraycopy(
        ByteArrays.toByteArray(length), 0,
        data, destPos, SHORT_SIZE_IN_BYTE
      );
      destPos += SHORT_SIZE_IN_BYTE;

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return
     */
    public short getSrcPort() {
      return srcPort;
    }

    /**
     *
     * @return
     */
    public int getSrcPortAsInt() {
      return (int)(0xFFFF & srcPort);
    }

    /**
     *
     * @return
     */
    public short getDstPort() {
      return dstPort;
    }

    /**
     *
     * @return
     */
    public int getDstPortAsInt() {
      return (int)(0xFFFF & dstPort);
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
      throw new UnsupportedOperationException();
    }

    /**
     *
     */
    @Deprecated
    @Override
    public boolean isValid() {
      throw new UnsupportedOperationException();
    }

    /**
     *
     * @param srcAddr
     * @param dstAddr
     * @return
     */
    private boolean verify(InetAddress srcAddr, InetAddress dstAddr) {
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

    /**
     *
     * @param srcAddr
     * @param dstAddr
     * @return
     */
    public boolean isValid(InetAddress srcAddr, InetAddress dstAddr) {
      Boolean result = validCache.getValue();
      if (result == null) {
        synchronized (validCache) {
          result = validCache.getValue();
          if (result == null) {
            result = verify(srcAddr, dstAddr);
            validCache.setValue(result);
          }
        }
      }
      return result.booleanValue();
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort));
      rawFields.add(ByteArrays.toByteArray(dstPort));
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

      sb.append("[UDP Header (")
        .append(length())
        .append(" bytes)]\n");
      sb.append("  Source port: ")
        .append(getSrcPortAsInt())
        .append("\n");
      sb.append("  Destination port: ")
        .append(getDstPortAsInt())
        .append("\n");
      sb.append("  Length: ")
        .append(getLengthAsInt())
        .append(" [bytes]\n");
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append("\n");

      return sb.toString();
    }

  }

}
