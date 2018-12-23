/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.LinuxSllPacketType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class LinuxSllPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -7743587634024281470L;

  private final LinuxSllHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new LinuxSllPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static LinuxSllPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new LinuxSllPacket(rawData, offset, length);
  }

  private LinuxSllPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new LinuxSllHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, EtherType.class)
              .newInstance(rawData, offset + header.length(), payloadLength, header.getProtocol());
    } else {
      this.payload = null;
    }
  }

  private LinuxSllPacket(Builder builder) {
    if (builder == null
        || builder.packetType == null
        || builder.addressType == null
        || builder.address == null
        || builder.protocol == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.packetType: ")
          .append(builder.packetType)
          .append(" builder.addressType: ")
          .append(builder.addressType)
          .append(" builder.address: ")
          .append(builder.address)
          .append(" builder.protocol: ")
          .append(builder.protocol);
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
    private ArpHardwareType addressType;
    private short addressLength;
    private byte[] address;
    private EtherType protocol;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    private Builder(LinuxSllPacket packet) {
      this.packetType = packet.header.packetType;
      this.addressType = packet.header.addressType;
      this.addressLength = packet.header.addressLength;
      this.address = packet.header.addressField;
      this.protocol = packet.header.protocol;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param packetType packetType
     * @return this Builder object for method chaining.
     */
    public Builder packetType(LinuxSllPacketType packetType) {
      this.packetType = packetType;
      return this;
    }

    /**
     * @param addressType addressType
     * @return this Builder object for method chaining.
     */
    public Builder addressType(ArpHardwareType addressType) {
      this.addressType = addressType;
      return this;
    }

    /**
     * @param addressLength addressLength
     * @return this Builder object for method chaining.
     */
    public Builder addressLength(short addressLength) {
      this.addressLength = addressLength;
      return this;
    }

    /**
     * @param address address
     * @return this Builder object for method chaining.
     */
    public Builder address(byte[] address) {
      this.address = address;
      return this;
    }

    /**
     * @param protocol protocol
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

    /** */
    private static final long serialVersionUID = -4946840737268934876L;

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
    private final ArpHardwareType addressType;
    private final short addressLength;
    private final byte[] addressField = new byte[ADDR_SIZE];
    private final LinkLayerAddress address;
    private final EtherType protocol;

    private LinuxSllHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
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

      this.packetType =
          LinuxSllPacketType.getInstance(ByteArrays.getShort(rawData, PPKTTYPE_OFFSET + offset));
      this.addressType =
          ArpHardwareType.getInstance(ByteArrays.getShort(rawData, PHATYPE_OFFSET + offset));
      this.addressLength = ByteArrays.getShort(rawData, HALEN_OFFSET + offset);
      if (getAddressLengthAsInt() > ADDR_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("addressLength must not be longer than ")
            .append(ADDR_SIZE)
            .append(" but it is: ")
            .append(getAddressLengthAsInt());
        throw new IllegalRawDataException(sb.toString());
      }
      System.arraycopy(rawData, ADDR_OFFSET + offset, addressField, 0, ADDR_SIZE);
      if (addressLength == 0) {
        this.address = null;
      } else {
        this.address =
            ByteArrays.getLinkLayerAddress(rawData, ADDR_OFFSET + offset, getAddressLengthAsInt());
      }
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
      if ((builder.addressLength & 0xFFFF) > ADDR_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("addressLength & 0xFFFF must not be longer than ")
            .append(ADDR_SIZE)
            .append(" but it is: ")
            .append(builder.addressLength & 0xFFFF);
        throw new IllegalArgumentException(sb.toString());
      }

      this.packetType = builder.packetType;
      this.addressType = builder.addressType;
      this.addressLength = builder.addressLength;
      System.arraycopy(builder.address, 0, addressField, 0, builder.address.length);
      this.protocol = builder.protocol;

      if (addressLength == 0) {
        this.address = null;
      } else {
        this.address = ByteArrays.getLinkLayerAddress(addressField, 0, getAddressLengthAsInt());
      }
    }

    /** @return packetType */
    public LinuxSllPacketType getPacketType() {
      return packetType;
    }

    /** @return addressType */
    public ArpHardwareType getAddressType() {
      return addressType;
    }

    /** @return addressLength */
    public short getAddressLength() {
      return addressLength;
    }

    /** @return addressLength */
    public int getAddressLengthAsInt() {
      return 0xFFFF & addressLength;
    }

    /** @return address, or null if the addressLength is 0. */
    public LinkLayerAddress getAddress() {
      return address;
    }

    /** @return address field */
    public byte[] getAddressField() {
      return ByteArrays.clone(addressField);
    }

    /** @return protocol */
    public EtherType getProtocol() {
      return protocol;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(packetType.value()));
      rawFields.add(ByteArrays.toByteArray(addressType.value()));
      rawFields.add(ByteArrays.toByteArray(addressLength));
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

      sb.append("[Linux SLL header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Packet Type: ").append(packetType).append(ls);
      sb.append("  Address Type: ").append(addressType).append(ls);
      sb.append("  Address Length: ").append(getAddressLengthAsInt()).append(ls);
      sb.append("  Address: ")
          .append(address)
          .append(" (")
          .append(ByteArrays.toHexString(addressField, " "))
          .append(")")
          .append(ls);
      sb.append("  Protocol: ").append(protocol).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      LinuxSllHeader other = (LinuxSllHeader) obj;
      return Arrays.equals(addressField, other.addressField)
          && packetType.equals(other.packetType)
          && protocol.equals(other.protocol)
          && addressType.equals(other.addressType)
          && addressLength == other.addressLength;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + packetType.hashCode();
      result = 31 * result + addressType.hashCode();
      result = 31 * result + addressLength;
      result = 31 * result + Arrays.hashCode(addressField);
      result = 31 * result + protocol.hashCode();
      return result;
    }
  }
}
