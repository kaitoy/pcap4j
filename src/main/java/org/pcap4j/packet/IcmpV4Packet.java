/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.IcmpV4TypeCode;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IcmpV4Packet extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 7643067752830062365L;

  private final IcmpV4Header header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return
   */
  public static IcmpV4Packet newPacket(byte[] rawData) {
    return new IcmpV4Packet(rawData);
  }

  private IcmpV4Packet(byte[] rawData) {
    this.header = new IcmpV4Header(rawData, this);
    this.payload
      = AnonymousPacket.newPacket(
          ByteArrays.getSubArray(
            rawData,
            IcmpV4Header.ICMP_HEADER_SIZE,
            rawData.length - IcmpV4Header.ICMP_HEADER_SIZE
          )
        );
  }

  private IcmpV4Packet(Builder builder) {
    if (
         builder == null
      || builder.typeCode == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IcmpV4Header(builder, this);
  }

  @Override
  public IcmpV4Header getHeader() {
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
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private IcmpV4TypeCode typeCode;
    private short checksum;
    private int typeSpecificField;
    private Packet.Builder payloadBuilder;
    private boolean validateAtBuild = true;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4Packet packet) {
      this.typeCode = packet.header.typeCode;
      this.checksum = packet.header.checksum;
      this.typeSpecificField = packet.header.typeSpecificField;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param typeCode
     * @return
     */
    public Builder typeCode(IcmpV4TypeCode typeCode) {
      this.typeCode = typeCode;
      return this;
    }

    /**
     *
     * @param checksum
     * @return
     */
    public Builder checksum(short checksum) {
      this.checksum = checksum;
      return this;
    }

    /**
     *
     * @param identifier
     * @return
     */
    public Builder identifier(short identifier) {
      this.typeSpecificField
        = (typeSpecificField & 0x0000FFFF) | (identifier << 16);
      return this;
    }

    /**
     *
     * @param sequenceNumber
     * @return
     */
    public Builder sequenceNumber(short sequenceNumber) {
      this.typeSpecificField
        = (typeSpecificField & 0xFFFF0000) | sequenceNumber;
      return this;
    }

    /**
     *
     * @param gatewayInternetAddress
     * @return
     */
    public Builder gatewayInternetAddress(InetAddress gatewayInternetAddress) {
      this.typeSpecificField
        = ByteArrays.getInt(gatewayInternetAddress.getAddress(), 0);
      return this;
    }

    /**
     *
     * @param pointer
     * @return
     */
    public Builder pointer(byte pointer) {
      this.typeSpecificField
        = (typeSpecificField & 0x00FFFFFF) | (pointer << 24);
      return this;
    }

    /**
     *
     * @param typeSpecificField
     * @return
     */
    public Builder typeSpecificField(int typeSpecificField) {
      this.typeSpecificField = typeSpecificField;
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
    public IcmpV4Packet build() {
      return new IcmpV4Packet(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public final class IcmpV4Header extends AbstractHeader {

    /**
     *
     */
    private static final long serialVersionUID = 752307079936231186L;

    private static final int TYPE_OFFSET
      = 0;
    private static final int TYPE_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int CODE_OFFSET
      = TYPE_OFFSET + TYPE_SIZE;
    private static final int CODE_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET
      = CODE_OFFSET + CODE_SIZE;
    private static final int CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TYPE_SPECIFIC_FIELD_OFFSET
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;
    private static final int TYPE_SPECIFIC_FIELD_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int ICMP_HEADER_SIZE
      = TYPE_SPECIFIC_FIELD_OFFSET + TYPE_SPECIFIC_FIELD_SIZE;

    private final IcmpV4TypeCode typeCode;
    private final short checksum;
    private final int typeSpecificField;

    private IcmpV4Header(byte[] rawData, IcmpV4Packet host) {
      if (rawData.length < ICMP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 header(")
          .append(ICMP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.typeCode
        = IcmpV4TypeCode
            .getInstance(ByteArrays.getShort(rawData, TYPE_OFFSET));
      this.checksum
        = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
      this.typeSpecificField
        = ByteArrays.getInt(rawData, TYPE_SPECIFIC_FIELD_OFFSET);
    }

    private IcmpV4Header(Builder builder, IcmpV4Packet host) {
      this.typeCode = builder.typeCode;
      this.typeSpecificField = builder.typeSpecificField;

      if (builder.validateAtBuild) {
        if (
          PacketPropertiesLoader.getInstance()
            .isEnabledIcmpChecksumVaridation()
        ) {
          this.checksum = calcChecksum();
        }
        else {
          this.checksum = (short)0;
        }
      }
      else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum() {
      byte[] data;
      int packetLength = IcmpV4Packet.this.payload.length() + length();

      if ((packetLength % 2) != 0) {
        data = new byte[packetLength + 1];
      }
      else {
        data = new byte[packetLength];
      }

      System.arraycopy(buildRawData(), 0, data, 0, length());
      System.arraycopy(
        IcmpV4Packet.this.payload.getRawData(), 0,
        data, length(), IcmpV4Packet.this.payload.length()
      );

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return
     */
    public IcmpV4TypeCode getTypeCode() {
      return typeCode;
    }

    /**
     *
     * @return
     */
    public short getChecksum() {
      return checksum;
    }

    /**
     *
     * @return
     */
    public short getIdentifier() {
      return (short)(typeSpecificField >> 16);
    }

    /**
     *
     * @return
     */
    public int getIdentifierAsInt() {
      return typeSpecificField >>> 16;
    }

    /**
     *
     * @return
     */
    public short getSequenceNumber() {
      return (short)typeSpecificField;
    }

    /**
     *
     * @return
     */
    public int getSequenceNumberAsInt() {
      return 0xFFFF & typeSpecificField;
    }

    /**
     *
     * @return
     */
    public InetAddress getGatewayInternetAddress() {
      try {
        return InetAddress.getByAddress(
                 ByteArrays.toByteArray(typeSpecificField)
               );
      } catch (UnknownHostException e) {
        throw new AssertionError("Never get here.");
      }
    }

    public byte getPointer() {
      return (byte)(typeSpecificField >> 24);
    }

    @Override
    protected boolean verify() {
      if (
        PacketPropertiesLoader.getInstance()
          .isEnabledIcmpChecksumVerification()
      ) {
        short cs = getChecksum();
        return cs == 0 ? true : (calcChecksum() == cs);
      }
      else {
        return true;
      }
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(typeCode.value()));
      rawFields.add(ByteArrays.toByteArray(checksum));
      rawFields.add(ByteArrays.toByteArray(typeSpecificField));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Type,Code: ")
        .append(typeCode)
        .append(ls);
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append(ls);

      switch (typeCode.getType()) {
        case 0:
        case 8:
        case 13:
        case 14:
        case 15:
        case 16:
          sb.append("  Identifier: ")
            .append(getIdentifierAsInt())
            .append(ls);
          sb.append("  Sequence number: ")
            .append(getSequenceNumberAsInt())
            .append(ls);
          break;
        case 3:
        case 4:
        case 11:
          sb.append("  Unused: ")
            .append(ByteArrays.toHexString(typeSpecificField, " "))
            .append(ls);
          break;
        case 5:
          sb.append("  Gateway Internet Address: ")
            .append(getGatewayInternetAddress())
            .append(ls);
          break;
        case 12:
          sb.append("  Pointer: ")
            .append(getPointer())
            .append(ls);
          sb.append("  Unused: ")
            .append(
               ByteArrays.toHexString(
                 (byte)(typeSpecificField >> 16),
                 " "
               )
             )
            .append(" ")
            .append(
               ByteArrays.toHexString(
                 (short)(typeSpecificField),
                 " "
               )
             )
            .append(ls);
          break;
        default:
          sb.append("  Unknown: ")
            .append(ByteArrays.toHexString(typeSpecificField, " "))
            .append(ls);
          break;
      }

      return sb.toString();
    }

  }

}
