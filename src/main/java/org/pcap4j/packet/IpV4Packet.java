/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;
import org.pcap4j.packet.namedvalue.IpNumber;
import org.pcap4j.packet.namedvalue.IpVersion;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;

public class IpV4Packet extends AbstractPacket implements L3Packet {

  private IpV4Header header;
  private Packet payload;

  public IpV4Packet() {
    this.header = new IpV4Header();
    this.payload = null;
  }

  public IpV4Packet(byte[] rawData) {
    this.header = new IpV4Header(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          IpV4Header.IPV4_HEADER_SIZE,
          this.header.getTotalLength() - IpV4Header.IPV4_HEADER_SIZE
        );

    this.payload
      = PacketFactory.getInstance()
          .newPacketByIpNumber(rawPayload, header.getProtocol().value());
  }

  @Override
  public IpV4Header getHeader() {
    return header;
  }

  @Override
  public void setPayload(Packet payload) {
    this.payload = payload;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public void validate() {
    if (payload != null) {
      if (payload instanceof UdpPacket) {
        ((UdpPacket)payload).setSrcAddr(header.getSrcAddr());
        ((UdpPacket)payload).setDstAddr(header.getDstAddr());
      }

      payload.validate();
    }
    if (header != null) {
      header.validate();
    }
  }

  @Override
  public boolean isValid() {
    if (payload != null) {
      if (payload instanceof UdpPacket) {
        ((UdpPacket)payload).setSrcAddr(header.getSrcAddr());
        ((UdpPacket)payload).setDstAddr(header.getDstAddr());
      }

      if (!payload.isValid()) {
        return false;
      }
    }

    if (header == null) {
      return false;
    }
    else {
      return header.isValid();
    }
  }

  public class IpV4Header extends AbstractHeader {

    private static final int VERSION_AND_IHL_OFFSET
      = 0;
    private static final int VERSION_AND_IHL_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int TOS_OFFSET
      = VERSION_AND_IHL_OFFSET + VERSION_AND_IHL_SIZE;
    private static final int TOS_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int TOTAL_LENGTH_OFFSET
      = TOS_OFFSET + TOS_SIZE;
    private static final int TOTAL_LENGTH_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int IDENTIFICATION_OFFSET
      = TOTAL_LENGTH_OFFSET + TOTAL_LENGTH_SIZE;
    private static final int IDENTIFICATION_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_OFFSET
      = IDENTIFICATION_OFFSET + IDENTIFICATION_SIZE;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int TTL_OFFSET
      = FLAGS_AND_FLAGMENT_OFFSET_OFFSET + FLAGS_AND_FLAGMENT_OFFSET_SIZE;
    private static final int TTL_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int PROTOCOL_OFFSET
      = TTL_OFFSET + TTL_SIZE;
    private static final int PROTOCOL_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int HEADER_CHECKSUM_OFFSET
      = PROTOCOL_OFFSET + PROTOCOL_SIZE;
    private static final int HEADER_CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int SRC_ADDR_OFFSET
      = HEADER_CHECKSUM_OFFSET + HEADER_CHECKSUM_SIZE;
    private static final int SRC_ADDR_SIZE
      = INT_SIZE_IN_BYTE;
    private static final int DST_ADDR_OFFSET
      = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int DST_ADDR_SIZE
      = INT_SIZE_IN_BYTE;
    private static final int IPV4_HEADER_SIZE
      = DST_ADDR_OFFSET + DST_ADDR_SIZE;
    // TODO options

    private IpVersion version;
    private byte ihl;
    private byte tos;
    private short totalLength;
    private short identification;
    private byte flags;
    private short flagmentOffset;
    private byte ttl;
    private IpNumber protocol;
    private short headerChecksum;
    private InetAddress srcAddr;
    private InetAddress dstAddr;

    private IpV4Header() {}

    private IpV4Header(byte[] rawHeader) {
      if (rawHeader.length < IPV4_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      byte versionAndIhl
        = ByteArrays.getByte(rawHeader, VERSION_AND_IHL_OFFSET);
      this.version = IpVersion.getInstance(
                       (byte)((versionAndIhl & 0xF0) >> 4)
                     );
      this.ihl = (byte)(versionAndIhl & 0x0F);

      this.tos
        = ByteArrays.getByte(rawHeader, TOS_OFFSET);
      this.totalLength
        = ByteArrays.getShort(rawHeader, TOTAL_LENGTH_OFFSET);
      this.identification
        = ByteArrays.getShort(rawHeader, IDENTIFICATION_OFFSET);

      short flagsAndFlagmentOffset
        = ByteArrays.getShort(rawHeader, FLAGS_AND_FLAGMENT_OFFSET_OFFSET);
      this.flags = (byte)((flagsAndFlagmentOffset & 0xE000) >> 13);
      this.flagmentOffset = (short)(flagsAndFlagmentOffset & 0x1FFF);

      this.ttl
        = ByteArrays.getByte(rawHeader, TTL_OFFSET);
      this.protocol
        = IpNumber
            .getInstance(ByteArrays.getByte(rawHeader, PROTOCOL_OFFSET));
      this.headerChecksum
        = ByteArrays.getShort(rawHeader, HEADER_CHECKSUM_OFFSET);
      this.srcAddr
        = ByteArrays.getInet4Address(rawHeader, SRC_ADDR_OFFSET);
      this.dstAddr
        = ByteArrays.getInet4Address(rawHeader, DST_ADDR_OFFSET);

      if (!version.equals(IpVersion.IPv4)) {
        throw new AssertionError();
      }
    }

    public IpVersion getVersion() {
      return version;
    }

    public int getVersionAsInt() {
      return (int)(0xFF & version.value());
    }

    public void setVersion(IpVersion version) {
      this.version = version;
    }

    public byte getIhl() {
      return ihl;
    }

    public int getIhlAsInt() {
      return (int)(0xFF & ihl);
    }

    public void setIhl(byte ihl) {
      if ((ihl & 0xF0) != 0) {
        throw new IllegalArgumentException(
                ihl + "is invalid value. "
                  + "IHL field of IP header must be between 0 and 15"
              );
      }
      this.ihl = ihl;
    }

    public byte getTos() {
      return tos;
    }

    public int getTosAsInt() {
      return (int)(0xFF & tos);
    }

    public void setTos(byte tos) {
      this.tos = tos;
    }

    public short getTotalLength() {
      return totalLength;
    }

    public int getTotalLengthAsInt() {
      return (int)(0xFFFF & totalLength);
    }

    public void setTotalLength(short totalLength) {
      this.totalLength = totalLength;
    }

    public short getIdentification() {
      return identification;
    }

    public int getIdentificationAsInt() {
      return (int)(0xFFFF & identification);
    }

    public void setIdentification(short identification) {
      this.identification = identification;
    }

    private byte getFlags() {
      return flags;
    }

    public boolean getReservedFlag() {
      return ((flags & 0x4) >> 2) != 0 ? true : false;
    }

    public boolean getDontFragmentFlag() {
      return ((flags & 0x2) >> 1) != 0 ? true : false;
    }

    public boolean getMoreFragmentFlag() {
      return ((flags & 0x1) >> 0) != 0 ? true : false;
    }

    private void setFlags(byte flags) {
      if ((flags & 0xFE) != 0) {
        throw new IllegalArgumentException(
                flags + "is invalid value. "
                  + "Flags field of IP header must be between 0 and 7"
              );
      }
      this.flags = flags;
    }

    public void setReservedFlag(boolean flag) {
      if (getReservedFlag() == flag) {
        return;
      }
      else {
        byte flags = getFlags();
        setFlags((byte)((flags & 3) | (~flags & 4)));
      }
    }

    public void setDontFragmentFlag(boolean flag) {
      if (getDontFragmentFlag() == flag) {
        return;
      }
      else {
        byte flags = getFlags();
        setFlags((byte)((flags & 5) | (~flags & 2)));
      }
    }

    public void setMoreFragmentFlag(boolean flag) {
      if (getMoreFragmentFlag() == flag) {
        return;
      }
      else {
        byte flags = getFlags();
        setFlags((byte)((flags & 6) | (~flags & 1)));
      }
    }

    public short getFlagmentOffset() {
      return flagmentOffset;
    }

    public int getFlagmentOffsetAsInt() {
      return (int)(flagmentOffset & 0xFFFF);
    }

    public void setFlagmentOffset(short flagmentOffset) {
      if ((flagmentOffset & 0xE000) != 0) {
        throw
          new IllegalArgumentException(
            flagmentOffset + "is invalid value. "
              + "FlagmentOffset field of IP header must be between 0 and 8191"
          );
      }
      this.flagmentOffset = flagmentOffset;
    }

    public byte getTtl() {
      return ttl;
    }

    public int getTtlAsInt() {
      return (int)(0xFF & ttl);
    }

    public void setTtl(byte ttl) {
      this.ttl = ttl;
    }

    public IpNumber getProtocol() {
      return protocol;
    }

    public void setProtocol(IpNumber protocol) {
      this.protocol = protocol;
    }

    public short getHeaderChecksum() {
      return headerChecksum;
    }

    public void setHeaderChecksum(short headerChecksum) {
      this.headerChecksum = headerChecksum;
    }

    public InetAddress getSrcAddr() {
      return srcAddr;
    }

    public void setSrcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
    }

    public InetAddress getDstAddr() {
      return dstAddr;
    }

    public void setDstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
    }

    @Override
    public void validate() {
      setVersion(IpVersion.IPv4);
      setIhl((byte)(length() / 4));
      setTotalLength((short)IpV4Packet.this.length());

      if (
        PacketPropertiesLoader.getInstance()
          .isEnableIpv4ChecksumVaridation()
      ) {
        setHeaderChecksum(calcHeaderChecksum());
      }
      else {
        setHeaderChecksum((short)0);
      }
    }

    private short calcHeaderChecksum() {
      byte[] data = getRawData();

      for (int i = 0; i < HEADER_CHECKSUM_SIZE; i++) {
        data[HEADER_CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    @Override
    public boolean isValid() {
      if (
          PacketPropertiesLoader.getInstance()
            .isEnableIpv4ChecksumVerification()
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
    public int length() {
      return IPV4_HEADER_SIZE;
    }

    @Override
    public byte[] getRawData() {
      byte[] data = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray((byte)((version.value() << 4) | ihl)), 0,
        data, VERSION_AND_IHL_OFFSET, VERSION_AND_IHL_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(tos), 0,
        data, TOS_OFFSET, TOS_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(totalLength), 0,
        data, TOTAL_LENGTH_OFFSET, TOTAL_LENGTH_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(identification), 0,
        data, IDENTIFICATION_OFFSET, IDENTIFICATION_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray((short)((flags << 13) | flagmentOffset)), 0,
        data, FLAGS_AND_FLAGMENT_OFFSET_OFFSET, FLAGS_AND_FLAGMENT_OFFSET_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(ttl), 0,
        data, TTL_OFFSET, TTL_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(protocol.value()), 0,
        data, PROTOCOL_OFFSET, PROTOCOL_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(headerChecksum), 0,
        data, HEADER_CHECKSUM_OFFSET, HEADER_CHECKSUM_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(srcAddr), 0,
        data, SRC_ADDR_OFFSET, SRC_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(dstAddr), 0,
        data, DST_ADDR_OFFSET, DST_ADDR_SIZE
      );
      return data;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();

      sb.append("[IPv4 Header (")
        .append(length())
        .append(" bytes)]\n");

      sb.append("  Version: ")
        .append(getVersionAsInt())
        .append("\n");

      sb.append("  IHL: ")
        .append(getIhlAsInt() * 4)
        .append(" [bytes]\n");

      sb.append("  TOS: ")
        .append(getTosAsInt())
        .append("\n");

      sb.append("  Total length: ")
        .append(getTotalLengthAsInt())
        .append(" [bytes]\n");

      sb.append("  Identification: ")
        .append(getIdentificationAsInt())
        .append("\n");

      sb.append("  Flags: (Reserved, Don't Fragment, More Fragment) = (")
        .append(getReservedFlag())
        .append(", ")
        .append(getDontFragmentFlag())
        .append(", ")
        .append(getMoreFragmentFlag())
        .append(")\n");

      sb.append("  Flagment offset: ")
        .append(getFlagmentOffsetAsInt())
        .append("\n");

      sb.append("  TTL: ")
        .append(getTtlAsInt())
        .append("\n");

      sb.append("  Protocol: ")
        .append(protocol)
        .append("\n");

      sb.append("  Header checksum: 0x")
        .append(ByteArrays.toHexString(headerChecksum, ""))
        .append("\n");

      sb.append("  Source address: ")
        .append(srcAddr)
        .append("\n");

      sb.append("  Destination address: ")
        .append(dstAddr)
        .append("\n");

      return sb.toString();
    }
  }

}
