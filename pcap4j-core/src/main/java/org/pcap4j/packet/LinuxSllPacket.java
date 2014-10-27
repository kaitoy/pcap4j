/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LinuxSllPacketType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.3.1
 */
public final class LinuxSllPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -7743587634024281470L;

  private final LinuxSllHeader header;
  private final Packet payload;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData
   * @param offset
   * @param length
   * @return a new LinuxSllPacket object.
   * @throws IllegalRawDataException
   */
  public static LinuxSllPacket newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new LinuxSllPacket(rawData, offset, length);
  }

  private LinuxSllPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    this.header = new LinuxSllHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload
        = PacketFactories.getFactory(Packet.class, EtherType.class)
            .newInstance(rawData, offset + header.length(), payloadLength, header.getProtocol());
    }
    else {
      this.payload = null;
    }
  }

  private LinuxSllPacket(Builder builder) {
    if (
         builder == null
      || builder.packetType == null
      || builder.hardwareType == null
      || builder.address == null
      || builder.protocol == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.packetType: ").append(builder.packetType)
        .append(" builder.hardwareType: ").append(builder.hardwareType)
        .append(" builder.address: ").append(builder.address)
        .append(" builder.protocol: ").append(builder.protocol);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new LinuxSllHeader(builder);
  }

  @Override
  public LinuxSllHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends AbstractBuilder {

    private LinuxSllPacketType packetType;
    private ArpHardwareType hardwareType;
    private short hardwareLength;
    private byte[] address;
    private EtherType protocol;
    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    private Builder(LinuxSllPacket packet)  {
      this.packetType = packet.header.packetType;
      this.hardwareType = packet.header.hardwareType;
      this.hardwareLength = packet.header.hardwareLength;
      this.address = packet.header.addressField;
      this.protocol = packet.header.protocol;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     *
     * @param packetType
     * @return this Builder object for method chaining.
     */
    public Builder packetType(LinuxSllPacketType packetType) {
      this.packetType = packetType;
      return this;
    }

    /**
     * @param hardwareType
     * @return this Builder object for method chaining.
     */
    public Builder hardwareType(ArpHardwareType hardwareType) {
      this.hardwareType = hardwareType;
      return this;
    }

    /**
     *
     * @param hardwareLength
     * @return this Builder object for method chaining.
     */
    public Builder hardwareLength(short hardwareLength) {
      this.hardwareLength = hardwareLength;
      return this;
    }

    /**
     *
     * @param address
     * @return this Builder object for method chaining.
     */
    public Builder address(byte[] address) {
      this.address = address;
      return this;
    }

    /**
     *
     * @param protocol
     * @return this Builder object for method chaining.
     */
    public Builder protocol(EtherType protocol) {
      this.protocol = protocol;
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

    @Override
    public LinuxSllPacket build() {
      return new LinuxSllPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class LinuxSllHeader extends AbstractHeader {

    /*
     * pcap/sll.h
     *
     * #define SLL_ADDRLEN  8   // length of address field
     *
     * struct sll_header {
     *   u_int16_t sll_pkttype;   // packet type
     *   u_int16_t sll_hatype;    // link-layer address type
     *   u_int16_t sll_halen;   // link-layer address length
     *   u_int8_t sll_addr[SLL_ADDRLEN];  // link-layer address
     *   u_int16_t sll_protocol;    // protocol
     * };
     */

    /**
     *
     */
    private static final long serialVersionUID = 8284608139785829230L;

    private static final int PPKTTYPE_OFFSET = 0;
    private static final int PPKTTYPE_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int PHATYPE_OFFSET = PPKTTYPE_OFFSET + PPKTTYPE_SIZE;
    private static final int PHATYPE_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int HALEN_OFFSET = PHATYPE_OFFSET + PHATYPE_SIZE;
    private static final int HALEN_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ADDR_OFFSET = HALEN_OFFSET + HALEN_SIZE;
    private static final int ADDR_SIZE = 8;
    private static final int PROTOCOL_OFFSET = ADDR_OFFSET + ADDR_SIZE;
    private static final int PROTOCOL_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int LINUX_SLL_HEADER_SIZE = PROTOCOL_OFFSET + PROTOCOL_SIZE;

    private final LinuxSllPacketType packetType;
    private final ArpHardwareType hardwareType;
    private final short hardwareLength;
    private final byte[] addressField = new byte[ADDR_SIZE];
    private final LinkLayerAddress address;
    private final EtherType protocol;

    private LinuxSllHeader(
      byte[] rawData, int offset, int length
    ) throws IllegalRawDataException {
      if (length < LINUX_SLL_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a Linux SLL header(")
          .append(LINUX_SLL_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.packetType
        = LinuxSllPacketType.getInstance(ByteArrays.getShort(rawData, PPKTTYPE_OFFSET + offset));
      this.hardwareType
        = ArpHardwareType.getInstance(ByteArrays.getShort(rawData, PHATYPE_OFFSET + offset));
      this.hardwareLength = ByteArrays.getShort(rawData, HALEN_OFFSET + offset);
      if (getHardwareLengthAsInt() > ADDR_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("hardwareLength must not be longer than ")
          .append(ADDR_SIZE)
          .append(" but it is: ")
          .append(getHardwareLengthAsInt());
        throw new IllegalRawDataException(sb.toString());
      }
      if (hardwareLength == 0) {
        throw new IllegalRawDataException("hardwareLength must not be 0.");
      }
      System.arraycopy(rawData, ADDR_OFFSET + offset, addressField, 0, ADDR_SIZE);
      this.address
        = ByteArrays.getLinkLayerAddress(rawData, ADDR_OFFSET + offset, getHardwareLengthAsInt());
      this.protocol = EtherType.getInstance(ByteArrays.getShort(rawData, PROTOCOL_OFFSET + offset));
    }

    private LinuxSllHeader(Builder builder) {
      if (builder.address.length > ADDR_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("address must not be longer than ")
          .append(ADDR_SIZE)
          .append(" but it is: ")
          .append(ByteArrays.toHexString(builder.address, " "));
        throw new IllegalArgumentException(sb.toString());
      }

      this.packetType = builder.packetType;
      this.hardwareType = builder.hardwareType;
      this.hardwareLength = builder.hardwareLength;
      System.arraycopy(builder.address, 0, addressField, 0, builder.address.length);
      this.protocol = builder.protocol;

      if (getHardwareLengthAsInt() > ADDR_SIZE) {
        this.address = LinkLayerAddress.getByAddress(addressField);
      }
      else {
        this.address
          = ByteArrays.getLinkLayerAddress(addressField, 0, getHardwareLengthAsInt());
      }
    }

    /**
     *
     * @return packetType
     */
    public LinuxSllPacketType getPacketType() {
      return packetType;
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
     * @return hardwareLength
     */
    public short getHardwareLength() {
      return hardwareLength;
    }

    /**
     *
     * @return hardwareLength
     */
    public int getHardwareLengthAsInt() {
      return 0xFFFF & hardwareLength;
    }


    /**
     *
     * @return address
     */
    public LinkLayerAddress getAddress() {
      return address;
    }

    /**
     * @return address field
     */
    public byte[] getAddressField() {
      return ByteArrays.clone(addressField);
    }

    /**
     *
     * @return protocol
     */
    public EtherType getProtocol() {
      return protocol;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(packetType.value()));
      rawFields.add(ByteArrays.toByteArray(hardwareType.value()));
      rawFields.add(ByteArrays.toByteArray(hardwareLength));
      rawFields.add(addressField);
      rawFields.add(ByteArrays.toByteArray(protocol.value()));
      return rawFields;
    }

    @Override
    public int length() {
      return LINUX_SLL_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Linux SLL header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Packet Type: ")
        .append(packetType)
        .append(ls);
      sb.append("  Hardware Type: ")
        .append(hardwareType)
        .append(ls);
      sb.append("  Hardware Length: ")
        .append(getHardwareLengthAsInt())
        .append(ls);
      sb.append("  Address: ")
        .append(address)
        .append(" (")
        .append(ByteArrays.toHexString(addressField, " "))
        .append(")")
        .append(ls);
      sb.append("  Protocol: ")
        .append(protocol)
        .append(ls);

      return sb.toString();
    }

  }

}
