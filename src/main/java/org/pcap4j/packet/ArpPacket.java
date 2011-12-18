/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;

import org.pcap4j.packet.namedvalue.ArpHardwareType;
import org.pcap4j.packet.namedvalue.ArpOperation;
import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.MAC_ADDRESS_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;

public class ArpPacket extends AbstractPacket implements L3Packet {

  private ArpHeader header;

  public ArpPacket() {
    this.header = new ArpHeader();
  }

  public ArpPacket(byte[] rawData) {
//    if (rawData.length != ArpHeader.ARP_HEADER_SIZE) {
//      throw new AssertionError();
//    }
//  ARP packet may be with ether trailer(padding). Only ignore it.
    this.header = new ArpHeader(rawData);
  }

  @Override
  public ArpHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return null;
  }

  @Override
  public void setPayload(Packet payload) {
    throw new UnsupportedOperationException();
  }

  public class ArpHeader extends AbstractHeader {

    private static final int HARDWARE_TYPE_OFFSET
      = 0;
    private static final int HARDWARE_TYPE_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int PROTOCOL_TYPE_OFFSET
      = HARDWARE_TYPE_OFFSET + HARDWARE_TYPE_SIZE;
    private static final int PROTOCOL_TYPE_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int HARDWARE_LENGTH_OFFSET
      = PROTOCOL_TYPE_OFFSET + PROTOCOL_TYPE_SIZE;
    private static final int HARDWARE_LENGTH_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int PROTOCOL_LENGTH_OFFSET
      = HARDWARE_LENGTH_OFFSET + HARDWARE_LENGTH_SIZE;
    private static final int PROTOCOL_LENGTH_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int OPERATION_OFFSET
      = PROTOCOL_LENGTH_OFFSET + PROTOCOL_LENGTH_SIZE;
    private static final int OPERATION_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int SRC_HARDWARE_ADDR_OFFSET
      = OPERATION_OFFSET + OPERATION_SIZE;
    private static final int SRC_HARDWARE_ADDR_SIZE
      = MAC_ADDRESS_SIZE_IN_BYTE;
    private static final int SRC_PROTOCOL_ADDR_OFFSET
      = SRC_HARDWARE_ADDR_OFFSET + SRC_HARDWARE_ADDR_SIZE;
    private static final int SRC_PROTOCOL_ADDR_SIZE
      = IP_ADDRESS_SIZE_IN_BYTE;
    private static final int DST_HARDWARE_ADDR_OFFSET
      = SRC_PROTOCOL_ADDR_OFFSET + SRC_PROTOCOL_ADDR_SIZE;
    private static final int DST_HARDWARE_ADDR_SIZE
      = MAC_ADDRESS_SIZE_IN_BYTE;
    private static final int DST_PROTOCOL_ADDR_OFFSET
      = DST_HARDWARE_ADDR_OFFSET + DST_HARDWARE_ADDR_SIZE;
    private static final int DST_PROTOCOL_ADDR_SIZE
      = IP_ADDRESS_SIZE_IN_BYTE;
    private static final int ARP_HEADER_SIZE
      = DST_PROTOCOL_ADDR_OFFSET + DST_PROTOCOL_ADDR_SIZE;

    private ArpHardwareType hardwareType;
    private EtherType protocolType;
    private byte hardwareLength;
    private byte protocolLength;
    private ArpOperation operation;
    private MacAddress srcHardwareAddr;
    private InetAddress srcProtocolAddr;
    private MacAddress dstHardwareAddr;
    private InetAddress dstProtocolAddr;

    private ArpHeader() {}

    private ArpHeader(byte[] rawHeader) {
      if (rawHeader.length < ARP_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.hardwareType
        = ArpHardwareType
            .getInstance(ByteArrays.getShort(rawHeader, HARDWARE_TYPE_OFFSET));
      this.protocolType
        = EtherType
            .getInstance(ByteArrays.getShort(rawHeader, PROTOCOL_TYPE_OFFSET));
      this.hardwareLength
        = ByteArrays.getByte(rawHeader, HARDWARE_LENGTH_OFFSET);
      this.protocolLength
        = ByteArrays.getByte(rawHeader, PROTOCOL_LENGTH_OFFSET);
      this.operation
        = ArpOperation
            .getInstance(ByteArrays.getShort(rawHeader, OPERATION_OFFSET));
      this.srcHardwareAddr
        = ByteArrays.getMacAddress(rawHeader, SRC_HARDWARE_ADDR_OFFSET);
      this.srcProtocolAddr
        = ByteArrays.getInet4Address(rawHeader, SRC_PROTOCOL_ADDR_OFFSET);
      this.dstHardwareAddr
        = ByteArrays.getMacAddress(rawHeader, DST_HARDWARE_ADDR_OFFSET);
      this.dstProtocolAddr
        = ByteArrays.getInet4Address(rawHeader, DST_PROTOCOL_ADDR_OFFSET);
    }

    public ArpHardwareType getHardwareType() {
      return hardwareType;
    }

    public void setHardwareType(ArpHardwareType hardwareType) {
      this.hardwareType = hardwareType;
    }

    public EtherType getProtocolType() {
      return protocolType;
    }

    public void setProtocolType(EtherType protocolType) {
      this.protocolType = protocolType;
    }

    public byte getHardwareLength() {
      return hardwareLength;
    }

    public int getHardwareLengthAsInt() {
      return (int)(0xFF & hardwareLength);
    }

    public void setHardwareLength(byte hardwareLength) {
      this.hardwareLength = hardwareLength;
    }

    public byte getProtocolLength() {
      return protocolLength;
    }

    public int getProtocolLengthAsInt() {
      return (int)(0xFF & protocolLength);
    }

    public void setProtocolLength(byte protocolLength) {
      this.protocolLength = protocolLength;
    }

    public ArpOperation getOperation() {
      return operation;
    }

    public void setOperation(ArpOperation operation) {
      this.operation = operation;
    }

    public MacAddress getSrcHardwareAddr() {
      return srcHardwareAddr;
    }

    public void setSrcHardwareAddr(MacAddress srcHardwareAddr) {
      this.srcHardwareAddr = srcHardwareAddr;
    }

    public InetAddress getSrcProtocolAddr() {
      return srcProtocolAddr;
    }

    public void setSrcProtocolAddr(InetAddress srcProtocolAddr) {
      this.srcProtocolAddr = srcProtocolAddr;
    }

    public MacAddress getDstHardwareAddr() {
      return dstHardwareAddr;
    }

    public void setDstHardwareAddr(MacAddress dstHardwareAddr) {
      this.dstHardwareAddr = dstHardwareAddr;
    }

    public InetAddress getDstProtocolAddr() {
      return dstProtocolAddr;
    }

    public void setDstProtocolAddr(InetAddress dstProtocolAddr) {
      this.dstProtocolAddr = dstProtocolAddr;
    }

    @Override
    public int length() { return ARP_HEADER_SIZE; }

    @Override
    public byte[] getRawData() {
      byte[] data = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray(hardwareType.value()), 0,
        data, HARDWARE_TYPE_OFFSET, HARDWARE_TYPE_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(protocolType.value()), 0,
        data, PROTOCOL_TYPE_OFFSET, PROTOCOL_TYPE_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(hardwareLength), 0,
        data, HARDWARE_LENGTH_OFFSET, HARDWARE_LENGTH_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(protocolLength), 0,
        data, PROTOCOL_LENGTH_OFFSET, PROTOCOL_LENGTH_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(operation.value()), 0,
        data, OPERATION_OFFSET, OPERATION_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(srcHardwareAddr), 0,
        data, SRC_HARDWARE_ADDR_OFFSET, SRC_HARDWARE_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(srcProtocolAddr), 0,
        data, SRC_PROTOCOL_ADDR_OFFSET, SRC_PROTOCOL_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(dstHardwareAddr), 0,
        data, DST_HARDWARE_ADDR_OFFSET, DST_HARDWARE_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(dstProtocolAddr), 0,
        data, DST_PROTOCOL_ADDR_OFFSET, DST_PROTOCOL_ADDR_SIZE
      );
      return data;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();

      sb.append("[ARP Header (")
        .append(length())
        .append(" bytes)]\n");

      sb.append("  Hardware type: ")
        .append(hardwareType)
        .append("\n");

      sb.append("  Protocol type: ")
        .append(protocolType)
        .append("\n");

      sb.append("  Hardware length: ")
        .append(getHardwareLengthAsInt())
        .append(" [bytes]\n");

      sb.append("  Protocol length: ")
        .append(getProtocolLengthAsInt())
        .append(" [bytes]\n");

      sb.append("  Operation: ")
        .append(operation)
        .append("\n");

      sb.append("  Source hardware address: ")
        .append(srcHardwareAddr)
        .append("\n");

      sb.append("  Source protocol address: ")
        .append(srcProtocolAddr)
        .append("\n");

      sb.append("  Destination hardware address: ")
        .append(dstHardwareAddr)
        .append("\n");

      sb.append("  Destination protocol address: ")
        .append(dstProtocolAddr)
        .append("\n");

      return sb.toString();
    }

  }

}
