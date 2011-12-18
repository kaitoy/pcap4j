/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;

import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import static org.pcap4j.util.ByteArrays.MAC_ADDRESS_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;

public class EthernetPacket extends AbstractPacket implements L2Packet {

  private static final int MIN_ETHERNET_PACKET_LENGTH = 60;

  private EthernetHeader header;
  private Packet payload;

  // Ethernet frame must be at least 60 bytes except FCS.
  // If it's less than 60 bytes, pad with this field.
  // Although this class handles padding, it's actually responsibility of NIF.
  private byte[] pad = new byte[0];

  public EthernetPacket() {
    this.header = new EthernetHeader();
    this.payload = null;
  }

  public EthernetPacket(byte[] rawData) {
    this.header = new EthernetHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          EthernetHeader.ETHERNET_HEADER_SIZE,
          rawData.length - EthernetHeader.ETHERNET_HEADER_SIZE
        );

    this.payload
      = PacketFactory.getInstance()
          .newPacketByEtherType(rawPayload, header.getType().value());

    if (rawData.length > length()) {
      this.pad
        = ByteArrays.getSubArray(
            rawData, length(), rawData.length - length()
          );
    }
  }

  @Override
  public EthernetHeader getHeader() {
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
    super.validate();
    if (length() < MIN_ETHERNET_PACKET_LENGTH) {
      pad = new byte[MIN_ETHERNET_PACKET_LENGTH - length()];
      Arrays.fill(pad, (byte)0);
    }
  }

  @Override
  public boolean isValid() {
    if (super.isValid()) {
      // A packet before padding may be captured. How do I verify?
      // return length() >= MIN_ETHERNET_PACKET_LENGTH;
      return true;
    }
    else {
      return false;
    }
  }

  @Override
  public int length() {
    int length = super.length();
    return length + pad.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = super.getRawData();
    if (pad.length != 0) {
      System.arraycopy(
        pad, 0, rawData, rawData.length - pad.length, pad.length
      );
    }
    return rawData;
  }

  public class EthernetHeader extends AbstractHeader {

    private static final int DST_ADDR_OFFSET = 0;
    private static final int DST_ADDR_SIZE = MAC_ADDRESS_SIZE_IN_BYTE;
    private static final int SRC_ADDR_OFFSET = DST_ADDR_OFFSET + DST_ADDR_SIZE;
    private static final int SRC_ADDR_SIZE = MAC_ADDRESS_SIZE_IN_BYTE;
    private static final int TYPE_OFFSET = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int TYPE_SIZE = SHORT_SIZE_IN_BYTE;
    private static final int ETHERNET_HEADER_SIZE = TYPE_OFFSET + TYPE_SIZE;

    private MacAddress dstAddr;
    private MacAddress srcAddr;
    private EtherType type;

    private EthernetHeader() {}

    private EthernetHeader(byte[] rawHeader) {
      if (rawHeader.length < ETHERNET_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.dstAddr = ByteArrays.getMacAddress(rawHeader, DST_ADDR_OFFSET);
      this.srcAddr = ByteArrays.getMacAddress(rawHeader, SRC_ADDR_OFFSET);
      this.type
        = EtherType.getInstance(ByteArrays.getShort(rawHeader, TYPE_OFFSET));
    }

    public void setDstAddr(MacAddress dstAddr) {
      this.dstAddr = dstAddr;
    }

    public MacAddress getDstAddr() {
      return dstAddr;
    }

    public void setSrcAddr(MacAddress srcAddr) {
      this.srcAddr = srcAddr;
    }

    public MacAddress getSrcAddr() {
      return srcAddr;
    }

    public void setType(EtherType type) {
      this.type = type;
    }

    public EtherType getType() {
      return type;
    }

    @Override
    public int length() {
      return ETHERNET_HEADER_SIZE;
    }

    @Override
    public byte[] getRawData() {
      byte[] data = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray(dstAddr), 0, data, DST_ADDR_OFFSET, DST_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(srcAddr), 0, data, SRC_ADDR_OFFSET, SRC_ADDR_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(type.value()), 0, data, TYPE_OFFSET, TYPE_SIZE
      );
      return data;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();

      sb.append("[Ethernet Header (")
        .append(length())
        .append(" bytes)]\n");

      sb.append("  Destination address: ")
        .append(dstAddr)
        .append("\n");

      sb.append("  Source address: ")
        .append(srcAddr)
        .append("\n");

      sb.append("  Type: ")
        .append(type)
        .append("\n");

      if (pad.length != 0) {
        sb.append("  Pad: 0x")
          .append(ByteArrays.toHexString(pad, ""))
          .append("\n");
      }

      return sb.toString();
    }

  }

}
