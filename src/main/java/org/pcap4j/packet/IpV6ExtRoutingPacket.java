/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INET6_ADDRESS_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6ExtRoutingPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -4454872145403587056L;

  private final IpV6ExtRoutingHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV6ExtRoutingPacket newPacket(byte[] rawData) {
    return new IpV6ExtRoutingPacket(rawData);
  }

  private IpV6ExtRoutingPacket(byte[] rawData) {
    this.header = new IpV6ExtRoutingHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = PacketFactories.getPacketFactory(IpNumber.class)
          .newPacket(rawPayload, header.getNextHeader());
  }

  private IpV6ExtRoutingPacket(Builder builder) {
    if (
         builder == null
      || builder.nextHeader == null
      || builder.typeSpecificData == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IpV6ExtRoutingHeader(builder);
  }

  @Override
  public IpV6ExtRoutingHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  protected boolean verify() {
    if (!(payload instanceof UdpPacket)) {
      if (!payload.isValid()) {
        return false;
      }
    }

    return header.isValid();
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class Builder extends AbstractBuilder {

    private IpNumber nextHeader;
    private byte hdrExtLen;
    private byte routingType;
    private byte segmentsLeft;
    private byte[] typeSpecificData;
    private List<Inet6Address> addresses = null;
    private Packet.Builder payloadBuilder;
    private boolean validateAtBuild = true;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    public Builder(IpV6ExtRoutingPacket packet) {
      this.nextHeader = packet.header.nextHeader;
      this.hdrExtLen = packet.header.hdrExtLen;
      this.routingType = packet.header.routingType;
      this.segmentsLeft = packet.header.segmentsLeft;
      this.typeSpecificData = packet.header.typeSpecificData;
      this.addresses = packet.header.addresses;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param nextHeader
     * @return
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     *
     * @param hdrExtLen
     * @return
     */
    public Builder hdrExtLen(byte hdrExtLen) {
      this.hdrExtLen = hdrExtLen;
      return this;
    }

    /**
     *
     * @param routingType
     * @return
     */
    public Builder routingType(byte routingType) {
      this.routingType = routingType;
      return this;
    }

    /**
     *
     * @param segmentsLeft
     * @return
     */
    public Builder segmentsLeft(byte segmentsLeft) {
      this.segmentsLeft = segmentsLeft;
      return this;
    }

    /**
     *
     * @param typeSpecificData
     * @return
     */
    public Builder typeSpecificData(byte[] typeSpecificData) {
      this.typeSpecificData = typeSpecificData;
      return this;
    }

    /**
     * This field is for routing type 0. This field would be used for building
     * typeSpecificData field of the packet instead of typeSpecificData field
     * of this if routingType == 0 && addresses != null.
     *
     * @param addresses
     * @return
     */
    public Builder addresses(List<Inet6Address> addresses) {
      this.addresses = addresses;
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
     *
     * @param validateAtBuild
     * @return
     */
    public Builder validateAtBuild(boolean validateAtBuild) {
      this.validateAtBuild = validateAtBuild;
      return this;
    }

    @Override
    public IpV6ExtRoutingPacket build() {
      return new IpV6ExtRoutingPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public final class IpV6ExtRoutingHeader extends AbstractHeader {

    /*
     *  0                               16                              32
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                                                               |
     *  .                                                               .
     *  .                       type-specific data                      .
     *  .                                                               .
     *  |                                                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 773193868313443164L;

    private static final int NEXT_HEADER_OFFSET
      = 0;
    private static final int NEXT_HEADER_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int HDR_EXT_LEN_OFFSET
      = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HDR_EXT_LEN_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int ROUTING_TYPE_OFFSET
      = HDR_EXT_LEN_OFFSET + HDR_EXT_LEN_SIZE;
    private static final int ROUTING_TYPE_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int SEGMENTS_LEFT_OFFSET
      = ROUTING_TYPE_OFFSET + ROUTING_TYPE_SIZE;
    private static final int SEGMENTS_LEFT_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int TYPE_SPECIFIC_DATA_OFFSET
      = SEGMENTS_LEFT_OFFSET + SEGMENTS_LEFT_SIZE;

    private final IpNumber nextHeader;
    private final byte hdrExtLen;
    private final byte routingType;
    private final byte segmentsLeft;
    private final byte[] typeSpecificData;
    private final List<Inet6Address> addresses;

    private IpV6ExtRoutingHeader(byte[] rawData) {
      if (rawData.length < 4) {
        StringBuilder sb = new StringBuilder(110);
        sb.append(
            "The data length of IPv6 routing header is must be more than 3. data: "
           )
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.nextHeader
        = IpNumber
            .getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET));
      this.hdrExtLen
        = ByteArrays.getByte(rawData, HDR_EXT_LEN_OFFSET);

      int headerLength = (hdrExtLen & 0xFF + 1) * 8;
      if (rawData.length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 routing header(")
          .append(headerLength)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.routingType
        = ByteArrays.getByte(rawData, ROUTING_TYPE_OFFSET);
      this.segmentsLeft
        = ByteArrays.getByte(rawData, SEGMENTS_LEFT_OFFSET);
      this.typeSpecificData
        = ByteArrays.getSubArray(
            rawData, TYPE_SPECIFIC_DATA_OFFSET, headerLength - 4
          );

      if (routingType == 0) {
        if (
             typeSpecificData.length < 4
          || (typeSpecificData.length - 4) % INET6_ADDRESS_SIZE_IN_BYTES != 0
        ) {
//          throw new IllegalPacketDataException(
//                  "Invalid typeSpecificData: "
//                    + ByteArrays.toHexString(typeSpecificData, " ")
//                );
          this.addresses = null;
        }
        else {
          this.addresses = new ArrayList<Inet6Address>();
          for (
            int offset = 4;
            offset < typeSpecificData.length;
            offset += INET6_ADDRESS_SIZE_IN_BYTES
          ) {
            try {
              addresses.add(
                (Inet6Address)Inet6Address.getByAddress(
                  ByteArrays.getSubArray(
                    typeSpecificData,
                    offset,
                    INET6_ADDRESS_SIZE_IN_BYTES
                  )
                )
              );
            } catch (UnknownHostException e) {
              throw new AssertionError("Never get here.");
            }
          }
        }
      }
      else {
        this.addresses = null;
      }
    }

    private IpV6ExtRoutingHeader(Builder builder) {
      if ((builder.typeSpecificData.length + 4) % 8 != 0) {
        throw new IllegalArgumentException(
                "typeSpecificData length is invalid."
                  + " (typeSpecificData.length + 4) % 8 must be 0."
                  + " typeSpecificData: "
                  + ByteArrays.toHexString(builder.typeSpecificData, " ")
              );
      }

      this.nextHeader = builder.nextHeader;
      this.routingType = builder.routingType;
      this.segmentsLeft = builder.segmentsLeft;

      if (routingType == 0 && builder.addresses != null) {
        this.addresses = builder.addresses;
        this.typeSpecificData
          = new byte[addresses.size() * INET6_ADDRESS_SIZE_IN_BYTES + 4];

        int offset = 4;
        for (Inet6Address addr: addresses) {
          System.arraycopy(
            addr.getAddress(), 0,
            typeSpecificData, offset, INET6_ADDRESS_SIZE_IN_BYTES
          );
        }
      }
      else {
        this.typeSpecificData = builder.typeSpecificData;
        this.addresses = null;
      }

      if (builder.validateAtBuild) {
        this.hdrExtLen = (byte)((typeSpecificData.length + 4) / 8 - 1);
      }
      else {
        this.hdrExtLen = builder.hdrExtLen;
      }
    }

    /**
     *
     * @return
     */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /**
     *
     * @return
     */
    public byte getHdrExtLen() {
      return hdrExtLen;
    }

    /**
     *
     * @return
     */
    public int getHdrExtLenAsInt() {
      return (int)(0xFF & hdrExtLen);
    }

    /**
     *
     * @return
     */
    public byte getRoutingType() {
      return routingType;
    }

    /**
     *
     * @return
     */
    public int getRoutingTypeAsInt() {
      return routingType & 0xFF;
    }

    /**
     *
     * @return
     */
    public byte getSegmentsLeft() {
      return segmentsLeft;
    }

    /**
     *
     * @return
     */
    public int getSegmentsLeftAsInt() {
      return segmentsLeft & 0xFF;
    }

    public byte[] getTypeSpecificData() {
      byte[] copy = new byte[typeSpecificData.length];
      System.arraycopy(typeSpecificData, 0, copy, 0, copy.length);
      return copy;
    }

    public List<Inet6Address> getAddresses() {
      return Collections.unmodifiableList(addresses);
    }

    @Override
    protected boolean verify() {
      return length() / 8 - 1 == getHdrExtLenAsInt();
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hdrExtLen));
      rawFields.add(ByteArrays.toByteArray(routingType));
      rawFields.add(ByteArrays.toByteArray(segmentsLeft));
      rawFields.add(getTypeSpecificData());
      return rawFields;
    }

    @Override
    public int measureLength() {
      return typeSpecificData.length + 4;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 Routing Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Next Header: ")
        .append(nextHeader)
        .append(ls);
      sb.append("  Hdr Ext Len: ")
        .append(getHdrExtLenAsInt())
        .append(ls);
      sb.append("  Routing Type: ")
        .append(getRoutingTypeAsInt())
        .append(ls);
      sb.append("  Segments Left: ")
        .append(getSegmentsLeftAsInt())
        .append(ls);

      if (routingType == 0 && addresses != null) {
        sb.append("  Reserved: ")
          .append(ByteArrays.toHexString(typeSpecificData, " ", 0, 4))
          .append(ls);

        int num = 0;
        for (Inet6Address addr: addresses) {
          sb.append("  Address[").append(num).append("]: ")
            .append(addr)
            .append(ls);
          num++;
        }
      }
      else {
        sb.append("  type-specific data: ")
          .append(ByteArrays.toHexString(typeSpecificData, " "))
          .append(ls);
      }

      return sb.toString();
    }

  }

}
