/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpV4Packet extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -3907669810080927342L;

  private final IpV4Header header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV4Packet newPacket(byte[] rawData) {
    return new IpV4Packet(rawData);
  }

  private IpV4Packet(byte[] rawData) {
    this.header = new IpV4Header(rawData, this);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          this.header.length(),
          this.header.getTotalLengthAsInt() - this.header.length()
        );

    this.payload
      = PacketFactories.getPacketFactory(IpNumber.class)
          .newPacket(rawPayload, header.getProtocol());
  }

  private IpV4Packet(Builder builder) {
    if (
         builder == null
      || builder.version == null
      || builder.protocol == null
      || builder.srcAddr == null
      || builder.dstAddr == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }

    if (builder.payloadBuilder instanceof UdpPacket.Builder) {
      ((UdpPacket.Builder)builder.payloadBuilder)
        .dstAddr(builder.dstAddr)
        .srcAddr(builder.srcAddr);
    }
    this.payload = builder.payloadBuilder.build();
    this.header = new IpV4Header(builder, this);
  }

  @Override
  public IpV4Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  protected boolean verify() {
    if (payload instanceof UdpPacket) {
      if (!((UdpPacket)payload).isValid(header.srcAddr, header.dstAddr)) {
        return false;
      }
    }
    else {
      if (!payload.isValid()) {
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
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private IpVersion version = IpVersion.IPv4;
    private byte ihl = (byte)5;
    private byte tos = (byte)0;
    private short totalLength;
    private short identification;
    private byte flags = (byte)0;
    private short flagmentOffset = (byte)0;
    private byte ttl;
    private IpNumber protocol;
    private short headerChecksum;
    private InetAddress srcAddr;
    private InetAddress dstAddr;
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
    public Builder(IpV4Packet packet) {
      this.version = packet.header.version;
      this.ihl = packet.header.ihl;
      this.tos = packet.header.tos;
      this.totalLength = packet.header.totalLength;
      this.identification = packet.header.identification;
      this.flags = packet.header.flags;
      this.flagmentOffset = packet.header.flagmentOffset;
      this.ttl = packet.header.ttl;
      this.protocol = packet.header.protocol;
      this.headerChecksum = packet.header.headerChecksum;
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
     * @param ihl
     * @return
     */
    public Builder ihl(byte ihl) {
      this.ihl = ihl;
      return this;
    }

    /**
     *
     * @param tos
     * @return
     */
    public Builder tos(byte tos) {
      this.tos = tos;
      return this;
    }

    /**
     *
     * @param totalLength
     * @return
     */
    public Builder totalLength(short totalLength) {
      this.totalLength = totalLength;
      return this;
    }

    /**
     *
     * @param identification
     * @return
     */
    public Builder identification(short identification) {
      this.identification = identification;
      return this;
    }

    /**
     *
     * @param flags
     * @return
     */
    public Builder flags(byte flags) {
      this.flags = flags;
      return this;
    }

    /**
     *
     * @param flag
     * @return
     */
    public Builder reservedFlag(boolean flag) {
      if (getReservedFlag() != flag) {
        this.flags = (byte)((flags & 3) | (~flags & 4));
      }
      return this;
    }

    /**
     *
     * @param flag
     * @return
     */
    public Builder dontFragmentFlag(boolean flag) {
      if (getDontFragmentFlag() != flag) {
        this.flags = (byte)((flags & 5) | (~flags & 2));
      }
      return this;
    }

    /**
     *
     * @param flag
     * @return
     */
    public Builder moreFragmentFlag(boolean flag) {
      if (getMoreFragmentFlag() != flag) {
        flags = (byte)((flags & 6) | (~flags & 1));
      }
      return this;
    }

    private boolean getReservedFlag() {
      return ((flags & 0x4) >> 2) != 0 ? true : false;
    }

    private boolean getDontFragmentFlag() {
      return ((flags & 0x2) >> 1) != 0 ? true : false;
    }

    private boolean getMoreFragmentFlag() {
      return ((flags & 0x1) >> 0) != 0 ? true : false;
    }

    /**
     *
     * @param flagmentOffset
     * @return
     */
    public Builder flagmentOffset(short flagmentOffset) {
      this.flagmentOffset = flagmentOffset;
      return this;
    }

    /**
     *
     * @param ttl
     * @return
     */
    public Builder ttl(byte ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     *
     * @param protocol
     * @return
     */
    public Builder protocol(IpNumber protocol) {
      this.protocol = protocol;
      return this;
    }

    /**
     *
     * @param headerChecksum
     * @return
     */
    public Builder headerChecksum(short headerChecksum) {
      this.headerChecksum = headerChecksum;
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
    public IpV4Packet build() {
      return new IpV4Packet(this);
    }

  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();

    if (header != null) {
      sb.append(header.toString());
    }
    if (payload != null) {
      if (
           (header != null)
        && (header.getMoreFragmentFlag() || header.getFlagmentOffset() != 0)
      ){
        String ls = System.getProperty("line.separator");

        sb.append("[Fragmented data (")
          .append(payload.length())
          .append(" bytes)]")
          .append(ls);
        sb.append("  Hex stream: ")
          .append(ByteArrays.toHexString(payload.getRawData(), " "))
          .append(ls);
      }
      else {
        sb.append(getPayload().toString());
      }
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public final class IpV4Header extends AbstractHeader {

    /**
     *
     */
    private static final long serialVersionUID = -337098234014128285L;

    private static final int VERSION_AND_IHL_OFFSET
      = 0;
    private static final int VERSION_AND_IHL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int TOS_OFFSET
      = VERSION_AND_IHL_OFFSET + VERSION_AND_IHL_SIZE;
    private static final int TOS_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int TOTAL_LENGTH_OFFSET
      = TOS_OFFSET + TOS_SIZE;
    private static final int TOTAL_LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int IDENTIFICATION_OFFSET
      = TOTAL_LENGTH_OFFSET + TOTAL_LENGTH_SIZE;
    private static final int IDENTIFICATION_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_OFFSET
      = IDENTIFICATION_OFFSET + IDENTIFICATION_SIZE;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TTL_OFFSET
      = FLAGS_AND_FLAGMENT_OFFSET_OFFSET + FLAGS_AND_FLAGMENT_OFFSET_SIZE;
    private static final int TTL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int PROTOCOL_OFFSET
      = TTL_OFFSET + TTL_SIZE;
    private static final int PROTOCOL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int HEADER_CHECKSUM_OFFSET
      = PROTOCOL_OFFSET + PROTOCOL_SIZE;
    private static final int HEADER_CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int SRC_ADDR_OFFSET
      = HEADER_CHECKSUM_OFFSET + HEADER_CHECKSUM_SIZE;
    private static final int SRC_ADDR_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int DST_ADDR_OFFSET
      = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int DST_ADDR_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int IPV4_HEADER_SIZE
      = DST_ADDR_OFFSET + DST_ADDR_SIZE;
    // TODO options

    private final IpVersion version;
    private final byte ihl;
    private final byte tos;
    private final short totalLength;
    private final short identification;
    private final byte flags;
    private final short flagmentOffset;
    private final byte ttl;
    private final IpNumber protocol;
    private final short headerChecksum;
    private final InetAddress srcAddr;
    private final InetAddress dstAddr;

    private IpV4Header(byte[] rawData, IpV4Packet host) {
      if (rawData.length < IPV4_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv4 header(")
          .append(IPV4_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      byte versionAndIhl
        = ByteArrays.getByte(rawData, VERSION_AND_IHL_OFFSET);
      this.version = IpVersion.getInstance(
                       (byte)((versionAndIhl & 0xF0) >> 4)
                     );
      this.ihl = (byte)(versionAndIhl & 0x0F);

      this.tos
        = ByteArrays.getByte(rawData, TOS_OFFSET);
      this.totalLength
        = ByteArrays.getShort(rawData, TOTAL_LENGTH_OFFSET);
      this.identification
        = ByteArrays.getShort(rawData, IDENTIFICATION_OFFSET);

      short flagsAndFlagmentOffset
        = ByteArrays.getShort(rawData, FLAGS_AND_FLAGMENT_OFFSET_OFFSET);
      this.flags = (byte)((flagsAndFlagmentOffset & 0xE000) >> 13);
      this.flagmentOffset = (short)(flagsAndFlagmentOffset & 0x1FFF);

      this.ttl
        = ByteArrays.getByte(rawData, TTL_OFFSET);
      this.protocol
        = IpNumber
            .getInstance(ByteArrays.getByte(rawData, PROTOCOL_OFFSET));
      this.headerChecksum
        = ByteArrays.getShort(rawData, HEADER_CHECKSUM_OFFSET);
      this.srcAddr
        = ByteArrays.getInet4Address(rawData, SRC_ADDR_OFFSET);
      this.dstAddr
        = ByteArrays.getInet4Address(rawData, DST_ADDR_OFFSET);
    }

    private IpV4Header(Builder builder, IpV4Packet host) {
      this.tos = builder.tos;
      this.identification = builder.identification;
      this.flags = builder.flags;
      this.flagmentOffset = builder.flagmentOffset;
      this.ttl = builder.ttl;
      this.protocol = builder.protocol;
      this.srcAddr = builder.srcAddr;
      this.dstAddr = builder.dstAddr;

      if (builder.validateAtBuild) {
        this.version = IpVersion.IPv4;
        this.ihl = (byte)(length() / 4);
        this.totalLength
          = (short)(host.payload.length() + length());

        if (
          PacketPropertiesLoader.getInstance()
            .isEnabledIpv4ChecksumVaridation()
        ) {
          headerChecksum = calcHeaderChecksum();
        }
        else {
          headerChecksum = (short)0;
        }
      }
      else {
        this.version = builder.version;
        this.ihl = builder.ihl;
        this.totalLength = builder.totalLength;
        this.headerChecksum = builder.headerChecksum;
      }
    }

    private short calcHeaderChecksum() {
      byte[] data = buildRawData();

      for (int i = 0; i < HEADER_CHECKSUM_SIZE; i++) {
        data[HEADER_CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
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
      return (int)(0xFF & version.value());
    }

    /**
     *
     * @return
     */
    public byte getIhl() {
      return ihl;
    }

    /**
     *
     * @return
     */
    public int getIhlAsInt() {
      return (int)(0xFF & ihl);
    }

    /**
     *
     * @return
     */
    public byte getTos() {
      return tos;
    }

    /**
     *
     * @return
     */
    public int getTosAsInt() {
      return (int)(0xFF & tos);
    }

    /**
     *
     * @return
     */
    public short getTotalLength() {
      return totalLength;
    }

    /**
     *
     * @return
     */
    public int getTotalLengthAsInt() {
      return (int)(0xFFFF & totalLength);
    }

    /**
     *
     * @return
     */
    public short getIdentification() {
      return identification;
    }

    /**
     *
     * @return
     */
    public int getIdentificationAsInt() {
      return (int)(0xFFFF & identification);
    }

    /**
     *
     * @return
     */
    public byte getFlags() {
      return flags;
    }

    /**
     *
     * @return
     */
    public boolean getReservedFlag() {
      return ((flags & 0x4) >> 2) != 0 ? true : false;
    }

    /**
     *
     * @return
     */
    public boolean getDontFragmentFlag() {
      return ((flags & 0x2) >> 1) != 0 ? true : false;
    }

    /**
     *
     * @return
     */
    public boolean getMoreFragmentFlag() {
      return ((flags & 0x1) >> 0) != 0 ? true : false;
    }

    /**
     *
     * @return
     */
    public short getFlagmentOffset() {
      return flagmentOffset;
    }

    /**
     *
     * @return
     */
    public int getFlagmentOffsetAsInt() {
      return (int)(flagmentOffset & 0xFFFF);
    }

    /**
     *
     * @return
     */
    public byte getTtl() {
      return ttl;
    }

    /**
     *
     * @return
     */
    public int getTtlAsInt() {
      return (int)(0xFF & ttl);
    }

    /**
     *
     * @return
     */
    public IpNumber getProtocol() {
      return protocol;
    }

    /**
     *
     * @return
     */
    public short getHeaderChecksum() {
      return headerChecksum;
    }

    /**
     *
     * @return
     */
    public InetAddress getSrcAddr() {
      return srcAddr;
    }

    /**
     *
     * @return
     */
    public InetAddress getDstAddr() {
      return dstAddr;
    }

    @Override
    protected boolean verify() {
      if (
          PacketPropertiesLoader.getInstance()
            .isEnabledIpv4ChecksumVerification()
        ) {
        short cs = getHeaderChecksum();
        return    ((byte)(length() / 4) == getIhl())
               && ((short)IpV4Packet.this.length() == getTotalLength())
               && (cs == 0 ? true : calcHeaderChecksum() == cs);
      }
      else {
        return true;
      }
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray((byte)((version.value() << 4) | ihl)));
      rawFields.add(ByteArrays.toByteArray(tos));
      rawFields.add(ByteArrays.toByteArray(totalLength));
      rawFields.add(ByteArrays.toByteArray(identification));
      rawFields.add(ByteArrays.toByteArray((short)((flags << 13) | flagmentOffset)));
      rawFields.add(ByteArrays.toByteArray(ttl));
      rawFields.add(ByteArrays.toByteArray(protocol.value()));
      rawFields.add(ByteArrays.toByteArray(headerChecksum));
      rawFields.add(ByteArrays.toByteArray(srcAddr));
      rawFields.add(ByteArrays.toByteArray(dstAddr));
      return rawFields;
    }

    @Override
    public int length() {
      return IPV4_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv4 Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Version: ")
        .append(getVersionAsInt())
        .append(ls);
      sb.append("  IHL: ")
        .append(getIhlAsInt() * 4)
        .append(" [bytes]")
        .append(ls);
      sb.append("  TOS: ")
        .append(getTosAsInt())
        .append(ls);
      sb.append("  Total length: ")
        .append(getTotalLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Identification: ")
        .append(getIdentificationAsInt())
        .append(ls);
      sb.append("  Flags: (Reserved, Don't Fragment, More Fragment) = (")
        .append(getReservedFlag())
        .append(", ")
        .append(getDontFragmentFlag())
        .append(", ")
        .append(getMoreFragmentFlag())
        .append(")")
        .append(ls);
      sb.append("  Flagment offset: ")
        .append(getFlagmentOffsetAsInt() * 8)
        .append(" [bytes]")
        .append(ls);
      sb.append("  TTL: ")
        .append(getTtlAsInt())
        .append(ls);
      sb.append("  Protocol: ")
        .append(protocol)
        .append(ls);
      sb.append("  Header checksum: 0x")
        .append(ByteArrays.toHexString(headerChecksum, ""))
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
