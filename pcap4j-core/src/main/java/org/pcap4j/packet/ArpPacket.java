/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ArpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 2232443026999119934L;

  private final ArpHeader header;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData
   * @param offset
   * @param length
   * @return a new ArpPacket object.
   * @throws IllegalRawDataException
   */
  public static ArpPacket newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new ArpPacket(rawData, offset, length);
  }

  private ArpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new ArpHeader(rawData, offset, length);
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
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.hardwareType: ").append(builder.hardwareType)
        .append(" builder.protocolType: ").append(builder.protocolType)
        .append(" builder.operation: ").append(builder.operation)
        .append(" builder.srcHardwareAddr: ").append(builder.srcHardwareAddr)
        .append(" builder.srcProtocolAddr: ").append(builder.srcProtocolAddr)
        .append(" builder.dstHardwareAddr: ").append(builder.dstHardwareAddr)
        .append(" builder.dstProtocolAddr: ").append(builder.dstProtocolAddr);
      throw new NullPointerException(sb.toString());
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
  public static final class Builder extends AbstractBuilder {

    private ArpHardwareType hardwareType;
    private EtherType protocolType;
    private byte hardwareLength;
    private byte protocolLength;
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
     * @return this Builder object for method chaining.
     */
    public Builder hardwareType(ArpHardwareType hardwareType) {
      this.hardwareType = hardwareType;
      return this;
    }

    /**
     *
     * @param protocolType
     * @return this Builder object for method chaining.
     */
    public Builder protocolType(EtherType protocolType) {
      this.protocolType = protocolType;
      return this;
    }

    /**
     *
     * @param hardwareLength
     * @return this Builder object for method chaining.
     */
    public Builder hardwareLength(byte hardwareLength) {
      this.hardwareLength = hardwareLength;
      return this;
    }

    /**
     *
     * @param protocolLength
     * @return this Builder object for method chaining.
     */
    public Builder protocolLength(byte protocolLength) {
      this.protocolLength = protocolLength;
      return this;
    }

    /**
     *
     * @param operation
     * @return this Builder object for method chaining.
     */
    public Builder operation(ArpOperation operation) {
      this.operation = operation;
      return this;
    }

    /**
     *
     * @param srcHardwareAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcHardwareAddr(MacAddress srcHardwareAddr) {
      this.srcHardwareAddr = srcHardwareAddr;
      return this;
    }

    /**
     *
     * @param srcProtocolAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcProtocolAddr(InetAddress srcProtocolAddr) {
      this.srcProtocolAddr = srcProtocolAddr;
      return this;
    }

    /**
     *
     * @param dstHardwareAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstHardwareAddr(MacAddress dstHardwareAddr) {
      this.dstHardwareAddr = dstHardwareAddr;
      return this;
    }

    /**
     *
     * @param dstProtocolAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstProtocolAddr(InetAddress dstProtocolAddr) {
      this.dstProtocolAddr = dstProtocolAddr;
      return this;
    }

    @Override
    public ArpPacket build() {
      return new ArpPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public static final class ArpHeader extends AbstractHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Hardware Type         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Protocol Type         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Hardware Length|Protocol Length|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Operation             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Src Hardware Address       |
     * +                               +
     * |                               |
     * +                               +
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Src Protocol Address       |
     * +                               |
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Dst Hardware Address       |
     * +                               +
     * |                               |
     * +                               +
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Dst Protocol Address       |
     * +                               |
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /**
     *
     */
    private static final long serialVersionUID = 2098135951321047828L;

    private static final int HARDWARE_TYPE_OFFSET
      = 0;
    private static final int HARDWARE_TYPE_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int PROTOCOL_TYPE_OFFSET
      = HARDWARE_TYPE_OFFSET + HARDWARE_TYPE_SIZE;
    private static final int PROTOCOL_TYPE_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int HARDWARE_LENGTH_OFFSET
      = PROTOCOL_TYPE_OFFSET + PROTOCOL_TYPE_SIZE;
    private static final int HARDWARE_LENGTH_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int PROTOCOL_LENGTH_OFFSET
      = HARDWARE_LENGTH_OFFSET + HARDWARE_LENGTH_SIZE;
    private static final int PROTOCOL_LENGTH_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int OPERATION_OFFSET
      = PROTOCOL_LENGTH_OFFSET + PROTOCOL_LENGTH_SIZE;
    private static final int OPERATION_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int SRC_HARDWARE_ADDR_OFFSET
      = OPERATION_OFFSET + OPERATION_SIZE;
    private static final int SRC_HARDWARE_ADDR_SIZE
      = MacAddress.SIZE_IN_BYTES;
    private static final int SRC_PROTOCOL_ADDR_OFFSET
      = SRC_HARDWARE_ADDR_OFFSET + SRC_HARDWARE_ADDR_SIZE;
    private static final int SRC_PROTOCOL_ADDR_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int DST_HARDWARE_ADDR_OFFSET
      = SRC_PROTOCOL_ADDR_OFFSET + SRC_PROTOCOL_ADDR_SIZE;
    private static final int DST_HARDWARE_ADDR_SIZE
      = MacAddress.SIZE_IN_BYTES;
    private static final int DST_PROTOCOL_ADDR_OFFSET
      = DST_HARDWARE_ADDR_OFFSET + DST_HARDWARE_ADDR_SIZE;
    private static final int DST_PROTOCOL_ADDR_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
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

    private ArpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < ARP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build an ARP header(")
          .append(ARP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.hardwareType
        = ArpHardwareType
            .getInstance(ByteArrays.getShort(rawData, HARDWARE_TYPE_OFFSET + offset));
      this.protocolType
        = EtherType
            .getInstance(ByteArrays.getShort(rawData, PROTOCOL_TYPE_OFFSET + offset));
      this.hardwareLength
        = ByteArrays.getByte(rawData, HARDWARE_LENGTH_OFFSET + offset);
      this.protocolLength
        = ByteArrays.getByte(rawData, PROTOCOL_LENGTH_OFFSET + offset);
      this.operation
        = ArpOperation
            .getInstance(ByteArrays.getShort(rawData, OPERATION_OFFSET + offset));
      this.srcHardwareAddr
        = ByteArrays.getMacAddress(rawData, SRC_HARDWARE_ADDR_OFFSET + offset);
      this.srcProtocolAddr
        = ByteArrays.getInet4Address(rawData, SRC_PROTOCOL_ADDR_OFFSET + offset);
      this.dstHardwareAddr
        = ByteArrays.getMacAddress(rawData, DST_HARDWARE_ADDR_OFFSET + offset);
      this.dstProtocolAddr
        = ByteArrays.getInet4Address(rawData, DST_PROTOCOL_ADDR_OFFSET + offset);
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
     * @return hardwareType
     */
    public ArpHardwareType getHardwareType() {
      return hardwareType;
    }

    /**
     *
     * @return protocolType
     */
    public EtherType getProtocolType() {
      return protocolType;
    }

    /**
     *
     * @return hardwareLength
     */
    public byte getHardwareLength() {
      return hardwareLength;
    }

    /**
     *
     * @return hardwareLength
     */
    public int getHardwareLengthAsInt() {
      return 0xFF & hardwareLength;
    }

    /**
     *
     * @return protocolLength
     */
    public byte getProtocolLength() {
      return protocolLength;
    }

    /**
     *
     * @return protocolLength
     */
    public int getProtocolLengthAsInt() {
      return 0xFF & protocolLength;
    }

    /**
     *
     * @return operation
     */
    public ArpOperation getOperation() {
      return operation;
    }

    /**
     *
     * @return srcHardwareAddr
     */
    public MacAddress getSrcHardwareAddr() {
      return srcHardwareAddr;
    }

    /**
     *
     * @return srcProtocolAddr
     */
    public InetAddress getSrcProtocolAddr() {
      return srcProtocolAddr;
    }

    /**
     *
     * @return dstHardwareAddr
     */
    public MacAddress getDstHardwareAddr() {
      return dstHardwareAddr;
    }

    /**
     *
     * @return dstProtocolAddr
     */
    public InetAddress getDstProtocolAddr() {
      return dstProtocolAddr;
    }

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
      String ls = System.getProperty("line.separator");

      sb.append("[ARP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Hardware type: ")
        .append(hardwareType)
        .append(ls);
      sb.append("  Protocol type: ")
        .append(protocolType)
        .append(ls);
      sb.append("  Hardware length: ")
        .append(getHardwareLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Protocol length: ")
        .append(getProtocolLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Operation: ")
        .append(operation)
        .append(ls);
      sb.append("  Source hardware address: ")
        .append(srcHardwareAddr)
        .append(ls);
      sb.append("  Source protocol address: ")
        .append(srcProtocolAddr)
        .append(ls);
      sb.append("  Destination hardware address: ")
        .append(dstHardwareAddr)
        .append(ls);
      sb.append("  Destination protocol address: ")
        .append(dstProtocolAddr)
        .append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }

      ArpHeader other = (ArpHeader)obj;
      return
           operation.equals(other.getOperation())
        && srcHardwareAddr.equals(other.srcHardwareAddr)
        && srcProtocolAddr.equals(other.srcProtocolAddr)
        && dstHardwareAddr.equals(other.dstHardwareAddr)
        && dstProtocolAddr.equals(other.dstProtocolAddr)
        && hardwareType.equals(other.hardwareType)
        && protocolType.equals(other.protocolType)
        && hardwareLength == other.hardwareLength
        && protocolLength == other.protocolLength;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + hardwareType.hashCode();
      result = 31 * result + protocolType.hashCode();
      result = 31 * result + hardwareLength;
      result = 31 * result + protocolLength;
      result = 31 * result + operation.hashCode();
      result = 31 * result + srcHardwareAddr.hashCode();
      result = 31 * result + srcProtocolAddr.hashCode();
      result = 31 * result + dstHardwareAddr.hashCode();
      result = 31 * result + dstProtocolAddr.hashCode();
      return result;
    }

  }

}
