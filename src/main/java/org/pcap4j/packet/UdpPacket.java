/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;

import java.net.InetAddress;

import org.pcap4j.packet.namedvalue.IpNumber;
import org.pcap4j.util.ByteArrays;

public class UdpPacket extends AbstractPacket implements L4Packet {

  private static final int PSEUDO_HEADER_SIZE = 12;

  private UdpHeader header;
  private Packet payload;

  // for pseudo header
  private InetAddress srcAddr = null;
  private InetAddress dstAddr = null;

  public UdpPacket() {
    this.header = new UdpHeader();
    this.payload = null;
  }

  public UdpPacket(byte[] rawData) {
    this.header = new UdpHeader(rawData);

    this.payload
      = new AnonymousPacket(
              ByteArrays.getSubArray(
                rawData,
                UdpHeader.UCP_HEADER_SIZE,
                rawData.length - UdpHeader.UCP_HEADER_SIZE
              )
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

  @Override
  public void setPayload(Packet payload) {
    this.payload = payload;
  }

  public void setSrcAddr(InetAddress srcAddr) {
    this.srcAddr = srcAddr;
  }

  public InetAddress getSrcAddr() {
    return srcAddr;
  }

  public void setDstAddr(InetAddress dstAddr) {
    this.dstAddr = dstAddr;
  }

  public InetAddress getDstAddr() {
    return dstAddr;
  }

  public class UdpHeader extends AbstractHeader {

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

    private short srcPort;
    private short dstPort;
    private short length;
    private short checksum;

    private UdpHeader() {}

    private UdpHeader(byte[] rawHeader) {
      if (rawHeader.length < UCP_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.srcPort = ByteArrays.getShort(rawHeader, SRC_PORT_OFFSET);
      this.dstPort = ByteArrays.getShort(rawHeader, DST_PORT_OFFSET);
      this.length = ByteArrays.getShort(rawHeader, LENGTH_OFFSET);
      this.checksum = ByteArrays.getShort(rawHeader, CHECKSUM_OFFSET);
    }

    public short getSrcPort() {
      return srcPort;
    }

    public int getSrcPortAsInt() {
      return (int)(0xFFFF & srcPort);
    }

    public void setSrcPort(short srcPort) {
      this.srcPort = srcPort;
    }

    public short getDstPort() {
      return dstPort;
    }

    public int getDstPortAsInt() {
      return (int)(0xFFFF & dstPort);
    }

    public void setDstPort(short dstPort) {
      this.dstPort = dstPort;
    }

    public short getLength() {
      return length;
    }

    public int getLengthAsInt() {
      return (int)(0xFFFF & length);
    }

    public void setLength(short length) {
      this.length = length;
    }

    public short getChecksum() {
      return checksum;
    }

    public void setChecksum(short checksum) {
      this.checksum = checksum;
    }

    @Override
    public int length() {
      return UCP_HEADER_SIZE;
    }

    @Override
    public void validate() {
      setLength((short)UdpPacket.this.length());

      if (
        PacketPropertiesLoader.getInstance()
          .isEnableUdpChecksumVaridation()
      ) {
        setChecksum(calcChecksum());
      }
      else {
        setChecksum((short)0);
      }
    }

    private short calcChecksum() {
      if (srcAddr == null || dstAddr == null) {
        throw new IllegalStateException(
                "Source or destination IP address is not set. src: "
                  + srcAddr + " dst: " + dstAddr
              );
      }

      byte[] data;
      int packetLength = UdpPacket.this.length();
      int destPos = 0;

      if ((packetLength % 2) != 0) {
        data = new byte[packetLength + 1 + PSEUDO_HEADER_SIZE];
        System.arraycopy(
          UdpPacket.this.getRawData(), 0, data, destPos, packetLength
        );
        destPos += packetLength;

        data[destPos] = (byte)0;
        destPos++;
      }
      else {
        data = new byte[packetLength + PSEUDO_HEADER_SIZE];
        System.arraycopy(
          UdpPacket.this.getRawData(), 0, data, destPos, packetLength
        );
        destPos += packetLength;
      }

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

    @Override
    public boolean isValid() {
      if (
        PacketPropertiesLoader.getInstance()
          .isEnableUdpChecksumVerification()
      ) {
        short cs = getChecksum();
        return    ((short)UdpPacket.this.length() != getLength())
               && (cs == 0 ? true : calcChecksum() != cs);
      }
      else {
        return true;
      }
    }

    @Override
    public byte[] getRawData() {
      byte[] data = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray(srcPort), 0,
        data, SRC_PORT_OFFSET, SRC_PORT_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(dstPort), 0,
        data, DST_PORT_OFFSET, DST_PORT_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(length), 0,
        data, LENGTH_OFFSET, LENGTH_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(checksum), 0,
        data, CHECKSUM_OFFSET, CHECKSUM_SIZE
      );
      return data;
    }

    @Override
    public String toString() {
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
