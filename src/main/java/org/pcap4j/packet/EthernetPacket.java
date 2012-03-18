/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

/**
 * This Class handles from DA to data.
 * Both preamble, SFD, and FCS are not contained.
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class EthernetPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 3461432646404254300L;

  private static final int MIN_ETHERNET_PAYLOAD_LENGTH = 46; // [bytes]
  //private static final int MAX_ETHERNET_PAYLOAD_LENGTH = 1500; // [bytes]

  private final EthernetHeader header;
  private final Packet payload;

  // Ethernet frame must be at least 60 bytes except FCS.
  // If it's less than 60 bytes, it's padded with this field.
  // Although this class handles pad, it's actually responsibility of NIF.
  private final byte[] pad;

  /**
   *
   * @param rawData
   * @return
   * @throws PacketException
   */
  public static EthernetPacket newPacket(byte[] rawData) {
    return new EthernetPacket(rawData);
  }

  private EthernetPacket(byte[] rawData) {
    this.header = new EthernetHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          this.header.length(),
          rawData.length - this.header.length()
        );

    this.payload
      = PacketFactories.getPacketFactory(EtherType.class)
          .newPacket(rawPayload, header.getType());

    int payloadLength = this.payload.length();
    if (rawPayload.length > payloadLength) {
      this.pad
        = ByteArrays.getSubArray(
            rawPayload, payloadLength, rawPayload.length - payloadLength
          );
    }
    else {
      this.pad = new byte[0];
    }
  }

  private EthernetPacket(Builder builder) {
    if (
         builder == null
      || builder.dstAddr == null
      || builder.srcAddr == null
      || builder.type == null
      || builder.payloadBuilder == null
      || builder.pad == null
    ) {
      throw new NullPointerException();
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new EthernetHeader(builder);

    int paddedPayloadLength
      = this.payload.length() + builder.pad.length;
    if (
         builder.validateAtBuild
      && paddedPayloadLength < MIN_ETHERNET_PAYLOAD_LENGTH
    ) {
      this.pad = new byte[
                   builder.pad.length
                     + MIN_ETHERNET_PAYLOAD_LENGTH - paddedPayloadLength
                 ];
    }
    else {
      this.pad = new byte[builder.pad.length];
    }
    System.arraycopy(
      builder.pad, 0, this.pad, 0, builder.pad.length
    );
  }

  @Override
  public EthernetHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

//  @Override
//  public boolean isValid() {
//    if (super.buildValid()) {
//      // A packet before padding may be captured. How do I verify?
//      return length() >= MIN_ETHERNET_PACKET_LENGTH;
//    }
//    else {
//      return false;
//    }
//  }

  @Override
  protected int measureLength() {
    int length = super.measureLength();
    length += pad.length;
    return length;
  }

  @Override
  protected byte[] buildRawData() {
    byte[] rawData = super.buildRawData();
    if (pad.length != 0) {
      System.arraycopy(
        pad, 0, rawData, rawData.length - pad.length, pad.length
      );
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
      sb.append("  Pad: 0x")
        .append(ByteArrays.toHexString(pad, " "))
        .append("\n");
    }

    return sb.toString();
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder implements Packet.Builder {

    private MacAddress dstAddr;
    private MacAddress srcAddr;
    private EtherType type;
    private Packet.Builder payloadBuilder;
    private byte[] pad = new byte[0];
    private boolean validateAtBuild = true;

    /**
     *
     */
    public Builder() {}

    private Builder(EthernetPacket packet) {
      this.dstAddr = packet.header.dstAddr;
      this.srcAddr = packet.header.srcAddr;
      this.type = packet.header.type;
      this.payloadBuilder = packet.payload.getBuilder();
      if (packet.pad != null) {
        this.pad = new byte[packet.pad.length];
        System.arraycopy(
          packet.pad, 0, this.pad, 0, packet.pad.length
        );
      }
    }

    /**
     *
     * @param dstAddr
     * @return
     */
    public Builder dstAddr(MacAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    /**
     *
     * @param srcAddr
     * @return
     */
    public Builder srcAddr(MacAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * @param type
     * @return
     */
    public Builder type(EtherType type) {
      this.type = type;
      return this;
    }

    /**
     *
     * @param payloadBuilder
     * @return
     */
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    /**
     *
     * @param pad
     * @return
     */
    public Builder pad(byte[] pad) {
      this.pad = pad;
      return this;
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

    public EthernetPacket build() {
      return new EthernetPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class EthernetHeader extends AbstractHeader {

    /**
     *
     */
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

    private EthernetHeader(byte[] rawData) {
      if (rawData.length < ETHERNET_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an Ethernet header(")
          .append(ETHERNET_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.dstAddr = ByteArrays.getMacAddress(rawData, DST_ADDR_OFFSET);
      this.srcAddr = ByteArrays.getMacAddress(rawData, SRC_ADDR_OFFSET);
      this.type
        = EtherType.getInstance(ByteArrays.getShort(rawData, TYPE_OFFSET));
    }

    private EthernetHeader(Builder builder) {
      this.dstAddr = builder.dstAddr;
      this.srcAddr = builder.srcAddr;
      this.type = builder.type;
    }

    /**
     *
     * @return
     */
    public MacAddress getDstAddr() {
      return dstAddr;
    }

    /**
     *
     * @return
     */
    public MacAddress getSrcAddr() {
      return srcAddr;
    }

    /**
     *
     * @return
     */
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

      return sb.toString();
    }

  }

}
