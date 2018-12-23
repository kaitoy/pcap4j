/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * This Class handles from DA to data. Both preamble, SFD, and FCS are not contained.
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class EthernetPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 3461432646404254300L;

  private static final int MIN_ETHERNET_PAYLOAD_LENGTH = 46; // [bytes]
  // private static final int MAX_ETHERNET_PAYLOAD_LENGTH = 1500; // [bytes]

  private final EthernetHeader header;
  private final Packet payload;

  // Ethernet frame must be at least 60 bytes except FCS.
  // If it's less than 60 bytes, it's padded with this field.
  // Although this class handles pad, it's actually responsibility of NIF.
  private final byte[] pad;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new EthernetPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static EthernetPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new EthernetPacket(rawData, offset, length);
  }

  private EthernetPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new EthernetHeader(rawData, offset, length);

    if ((header.getType().value() & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
      int payloadLength = header.getType().value();
      int padLength = length - header.length() - payloadLength;
      int payloadOffset = offset + header.length();

      if (padLength < 0) {
        throw new IllegalRawDataException(
            "The value of the ether type (length) field seems to be wrong: "
                + header.getType().value());
      }

      if (payloadLength > 0) {
        this.payload =
            PacketFactories.getFactory(Packet.class, EtherType.class)
                .newInstance(rawData, payloadOffset, payloadLength, header.getType());
      } else { // payloadLength == 0
        this.payload = null;
      }

      if (padLength > 0) {
        this.pad = ByteArrays.getSubArray(rawData, payloadOffset + payloadLength, padLength);
      } else {
        this.pad = new byte[0];
      }
    } else {
      int payloadAndPadLength = length - header.length();
      if (payloadAndPadLength > 0) {
        int payloadOffset = offset + header.length();
        this.payload =
            PacketFactories.getFactory(Packet.class, EtherType.class)
                .newInstance(rawData, payloadOffset, payloadAndPadLength, header.getType());

        int padLength = payloadAndPadLength - payload.length();
        if (padLength > 0) {
          this.pad = ByteArrays.getSubArray(rawData, payloadOffset + payload.length(), padLength);
        } else {
          this.pad = new byte[0];
        }
      } else {
        this.payload = null;
        this.pad = new byte[0];
      }
    }
  }

  private EthernetPacket(Builder builder) {
    if (builder == null
        || builder.dstAddr == null
        || builder.srcAddr == null
        || builder.type == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.dstAddr: ")
          .append(builder.dstAddr)
          .append(" builder.srcAddr: ")
          .append(builder.srcAddr)
          .append(" builder.type: ")
          .append(builder.type);
      throw new NullPointerException(sb.toString());
    }

    if (!builder.paddingAtBuild && builder.pad == null) {
      throw new NullPointerException(
          "builder.pad must not be null" + " if builder.paddingAtBuild is false");
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new EthernetHeader(builder);

    int payloadLength = payload != null ? payload.length() : 0;
    if (builder.paddingAtBuild) {
      if (payloadLength < MIN_ETHERNET_PAYLOAD_LENGTH) {
        this.pad = new byte[MIN_ETHERNET_PAYLOAD_LENGTH - payloadLength];
      } else {
        this.pad = new byte[0];
      }
    } else {
      this.pad = new byte[builder.pad.length];
      System.arraycopy(builder.pad, 0, this.pad, 0, builder.pad.length);
    }
  }

  @Override
  public EthernetHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  /** @return pad */
  public byte[] getPad() {
    byte[] copy = new byte[pad.length];
    System.arraycopy(pad, 0, copy, 0, pad.length);
    return copy;
  }

  @Override
  protected int calcLength() {
    int length = super.calcLength();
    length += pad.length;
    return length;
  }

  @Override
  protected byte[] buildRawData() {
    byte[] rawData = super.buildRawData();
    if (pad.length != 0) {
      System.arraycopy(pad, 0, rawData, rawData.length - pad.length, pad.length);
    }
    return rawData;
  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();

    sb.append(header.toString());
    if (payload != null) {
      sb.append(payload.toString());
    }
    if (pad.length != 0) {
      String ls = System.getProperty("line.separator");
      sb.append("[Ethernet Pad (")
          .append(pad.length)
          .append(" bytes)]")
          .append(ls)
          .append("  Hex stream: ")
          .append(ByteArrays.toHexString(pad, " "))
          .append(ls);
    }

    return sb.toString();
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public boolean equals(Object obj) {
    if (super.equals(obj)) {
      EthernetPacket other = (EthernetPacket) obj;
      return Arrays.equals(pad, other.pad);
    } else {
      return false;
    }
  }

  @Override
  protected int calcHashCode() {
    return 31 * super.calcHashCode() + Arrays.hashCode(pad);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private MacAddress dstAddr;
    private MacAddress srcAddr;
    private EtherType type;
    private Packet.Builder payloadBuilder;
    private byte[] pad;
    private boolean paddingAtBuild;

    /** */
    public Builder() {}

    private Builder(EthernetPacket packet) {
      this.dstAddr = packet.header.dstAddr;
      this.srcAddr = packet.header.srcAddr;
      this.type = packet.header.type;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
      this.pad = packet.pad;
    }

    /**
     * @param dstAddr dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(MacAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    /**
     * @param srcAddr srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(MacAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(EtherType type) {
      this.type = type;
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
     * @param pad pad
     * @return this Builder object for method chaining.
     */
    public Builder pad(byte[] pad) {
      this.pad = pad;
      return this;
    }

    /**
     * @param paddingAtBuild paddingAtBuild
     * @return this Builder object for method chaining.
     */
    public Builder paddingAtBuild(boolean paddingAtBuild) {
      this.paddingAtBuild = paddingAtBuild;
      return this;
    }

    @Override
    public EthernetPacket build() {
      return new EthernetPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class EthernetHeader extends AbstractHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Dst Hardware Address       |
     * +                               +
     * |                               |
     * +                               +
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Src Hardware Address       |
     * +                               +
     * |                               |
     * +                               +
     * |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Type                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /** */
    private static final long serialVersionUID = -8271269099161190389L;

    private static final int DST_ADDR_OFFSET = 0;
    private static final int DST_ADDR_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int SRC_ADDR_OFFSET = DST_ADDR_OFFSET + DST_ADDR_SIZE;
    private static final int SRC_ADDR_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int TYPE_OFFSET = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int TYPE_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ETHERNET_HEADER_SIZE = TYPE_OFFSET + TYPE_SIZE;

    private final MacAddress dstAddr;
    private final MacAddress srcAddr;
    private final EtherType type;

    private EthernetHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < ETHERNET_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an Ethernet header(")
            .append(ETHERNET_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.dstAddr = ByteArrays.getMacAddress(rawData, DST_ADDR_OFFSET + offset);
      this.srcAddr = ByteArrays.getMacAddress(rawData, SRC_ADDR_OFFSET + offset);
      this.type = EtherType.getInstance(ByteArrays.getShort(rawData, TYPE_OFFSET + offset));
    }

    private EthernetHeader(Builder builder) {
      this.dstAddr = builder.dstAddr;
      this.srcAddr = builder.srcAddr;
      this.type = builder.type;
    }

    /** @return dstAddr */
    public MacAddress getDstAddr() {
      return dstAddr;
    }

    /** @return srcAddr */
    public MacAddress getSrcAddr() {
      return srcAddr;
    }

    /** @return type */
    public EtherType getType() {
      return type;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(dstAddr));
      rawFields.add(ByteArrays.toByteArray(srcAddr));
      rawFields.add(ByteArrays.toByteArray(type.value()));
      return rawFields;
    }

    @Override
    public int length() {
      return ETHERNET_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Ethernet Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Destination address: ").append(dstAddr).append(ls);
      sb.append("  Source address: ").append(srcAddr).append(ls);
      sb.append("  Type: ").append(type).append(ls);

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

      EthernetHeader other = (EthernetHeader) obj;
      return dstAddr.equals(other.dstAddr)
          && srcAddr.equals(other.srcAddr)
          && type.equals(other.type);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + dstAddr.hashCode();
      result = 31 * result + srcAddr.hashCode();
      result = 31 * result + type.hashCode();
      return result;
    }
  }
}
