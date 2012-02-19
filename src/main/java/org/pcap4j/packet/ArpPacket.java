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
import org.pcap4j.packet.namedvalue.ArpHardwareType;
import org.pcap4j.packet.namedvalue.ArpOperation;
import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.MAC_ADDRESS_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ArpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 2232443026999119934L;

  private transient final ArpHeader header;

  /**
   *
   * @param rawData
   * @return
   */
  public static ArpPacket newPacket(byte[] rawData) {
    return new ArpPacket(rawData);
  }

  private ArpPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException();
    }
    this.header = new ArpHeader(rawData);
  }

  private ArpPacket(Builder builder) {
    if (
         builder == null
      || builder.hardwareType == null
      || builder.protocolType == null
      || builder.operation == null
      || builder.srcHardwareAddr == null
      || builder.srcProtocolAddr == null
      || builder.dstHardwareAddr == null
      || builder.dstProtocolAddr == null
    ) {
      throw new NullPointerException();
    }

    this.header = new ArpHeader(builder);
  }

  @Override
  public ArpHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   *
   * @author Kaito Yamada
   *
   */
  public static final class Builder implements Packet.Builder {

    private ArpHardwareType hardwareType = ArpHardwareType.ETHERNET;
    private EtherType protocolType = EtherType.IPV4;
    private byte hardwareLength = (byte)ByteArrays.MAC_ADDRESS_SIZE_IN_BYTE;
    private byte protocolLength = (byte)ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;
    private ArpOperation operation;
    private MacAddress srcHardwareAddr;
    private InetAddress srcProtocolAddr;
    private MacAddress dstHardwareAddr;
    private InetAddress dstProtocolAddr;

    /**
     *
     */
    public Builder() {}

    private Builder(ArpPacket packet) {
      this.hardwareType = packet.header.hardwareType;
      this.protocolType = packet.header.protocolType;
      this.hardwareLength = packet.header.hardwareLength;
      this.protocolLength = packet.header.protocolLength;
      this.operation = packet.header.operation;
      this.srcHardwareAddr = packet.header.srcHardwareAddr;
      this.srcProtocolAddr = packet.header.srcProtocolAddr;
      this.dstHardwareAddr = packet.header.dstHardwareAddr;
      this.dstProtocolAddr = packet.header.dstProtocolAddr;
    }

    /**
     *
     * @param hardwareType
     * @return
     */
    public Builder hardwareType(ArpHardwareType hardwareType) {
      this.hardwareType = hardwareType;
      return this;
    }

    /**
     *
     * @param protocolType
     * @return
     */
    public Builder protocolType(EtherType protocolType) {
      this.protocolType = protocolType;
      return this;
    }

    /**
     *
     * @param hardwareLength
     * @return
     */
    public Builder hardwareLength(byte hardwareLength) {
      this.hardwareLength = hardwareLength;
      return this;
    }

    /**
     *
     * @param protocolLength
     * @return
     */
    public Builder protocolLength(byte protocolLength) {
      this.protocolLength = protocolLength;
      return this;
    }

    /**
     *
     * @param operation
     * @return
     */
    public Builder operation(ArpOperation operation) {
      this.operation = operation;
      return this;
    }

    /**
     *
     * @param srcHardwareAddr
     * @return
     */
    public Builder srcHardwareAddr(MacAddress srcHardwareAddr) {
      this.srcHardwareAddr = srcHardwareAddr;
      return this;
    }

    /**
     *
     * @param srcProtocolAddr
     * @return
     */
    public Builder srcProtocolAddr(InetAddress srcProtocolAddr) {
      this.srcProtocolAddr = srcProtocolAddr;
      return this;
    }

    /**
     *
     * @param dstHardwareAddr
     * @return
     */
    public Builder dstHardwareAddr(MacAddress dstHardwareAddr) {
      this.dstHardwareAddr = dstHardwareAddr;
      return this;
    }

    /**
     *
     * @param dstProtocolAddr
     * @return
     */
    public Builder dstProtocolAddr(InetAddress dstProtocolAddr) {
      this.dstProtocolAddr = dstProtocolAddr;
      return this;
    }

    public ArpPacket build() {
      return new ArpPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public final class ArpHeader extends AbstractHeader {

    /**
     *
     */
    private static final long serialVersionUID = 2098135951321047828L;

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

    private final ArpHardwareType hardwareType;
    private final EtherType protocolType;
    private final byte hardwareLength;
    private final byte protocolLength;
    private final ArpOperation operation;
    private final MacAddress srcHardwareAddr;
    private final InetAddress srcProtocolAddr;
    private final MacAddress dstHardwareAddr;
    private final InetAddress dstProtocolAddr;

    private ArpHeader(byte[] rawData) {
      if (rawData.length < ARP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an ARP header(")
          .append(ARP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.hardwareType
        = ArpHardwareType
            .getInstance(ByteArrays.getShort(rawData, HARDWARE_TYPE_OFFSET));
      this.protocolType
        = EtherType
            .getInstance(ByteArrays.getShort(rawData, PROTOCOL_TYPE_OFFSET));
      this.hardwareLength
        = ByteArrays.getByte(rawData, HARDWARE_LENGTH_OFFSET);
      this.protocolLength
        = ByteArrays.getByte(rawData, PROTOCOL_LENGTH_OFFSET);
      this.operation
        = ArpOperation
            .getInstance(ByteArrays.getShort(rawData, OPERATION_OFFSET));
      this.srcHardwareAddr
        = ByteArrays.getMacAddress(rawData, SRC_HARDWARE_ADDR_OFFSET);
      this.srcProtocolAddr
        = ByteArrays.getInet4Address(rawData, SRC_PROTOCOL_ADDR_OFFSET);
      this.dstHardwareAddr
        = ByteArrays.getMacAddress(rawData, DST_HARDWARE_ADDR_OFFSET);
      this.dstProtocolAddr
        = ByteArrays.getInet4Address(rawData, DST_PROTOCOL_ADDR_OFFSET);
    }

    private ArpHeader(Builder builder) {
      this.hardwareType = builder.hardwareType;
      this.protocolType = builder.protocolType;
      this.hardwareLength = builder.hardwareLength;
      this.protocolLength = builder.protocolLength;
      this.operation = builder.operation;
      this.srcHardwareAddr = builder.srcHardwareAddr;
      this.srcProtocolAddr = builder.srcProtocolAddr;
      this.dstHardwareAddr = builder.dstHardwareAddr;
      this.dstProtocolAddr = builder.dstProtocolAddr;
    }

    /**
     *
     * @return
     */
    public ArpHardwareType getHardwareType() {
      return hardwareType;
    }

    /**
     *
     * @return
     */
    public EtherType getProtocolType() {
      return protocolType;
    }

    /**
     *
     * @return
     */
    public byte getHardwareLength() {
      return hardwareLength;
    }

    /**
     *
     * @return
     */
    public int getHardwareLengthAsInt() {
      return (int)(0xFF & hardwareLength);
    }

    /**
     *
     * @return
     */
    public byte getProtocolLength() {
      return protocolLength;
    }

    /**
     *
     * @return
     */
    public int getProtocolLengthAsInt() {
      return (int)(0xFF & protocolLength);
    }

    /**
     *
     * @return
     */
    public ArpOperation getOperation() {
      return operation;
    }

    /**
     *
     * @return
     */
    public MacAddress getSrcHardwareAddr() {
      return srcHardwareAddr;
    }

    /**
     *
     * @return
     */
    public InetAddress getSrcProtocolAddr() {
      return srcProtocolAddr;
    }

    /**
     *
     * @return
     */
    public MacAddress getDstHardwareAddr() {
      return dstHardwareAddr;
    }

    /**
     *
     * @return
     */
    public InetAddress getDstProtocolAddr() {
      return dstProtocolAddr;
    }

    @Override
    public boolean isValid() { return true; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(hardwareType.value()));
      rawFields.add(ByteArrays.toByteArray(protocolType.value()));
      rawFields.add(ByteArrays.toByteArray(hardwareLength));
      rawFields.add(ByteArrays.toByteArray(protocolLength));
      rawFields.add(ByteArrays.toByteArray(operation.value()));
      rawFields.add(ByteArrays.toByteArray(srcHardwareAddr));
      rawFields.add(ByteArrays.toByteArray(srcProtocolAddr));
      rawFields.add(ByteArrays.toByteArray(dstHardwareAddr));
      rawFields.add(ByteArrays.toByteArray(dstProtocolAddr));
      return rawFields;
    }

    @Override
    public int length() { return ARP_HEADER_SIZE; }

    @Override
    protected String buildString() {
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
