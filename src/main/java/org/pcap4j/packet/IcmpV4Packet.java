/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTE;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTE;
import org.pcap4j.packet.namedvalue.IcmpV4TypeCode;
import org.pcap4j.util.ByteArrays;

public final class IcmpV4Packet extends AbstractPacket implements L4Packet {

  private final IcmpV4Header header;
  private final Packet payload;

  public IcmpV4Packet(byte[] rawData) {
    this.header = new IcmpV4Header(rawData);
    this.payload
      = new AnonymousPacket(
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
      || builder.payload == null
    ) {
      throw new NullPointerException();
    }

    this.payload = builder.payload;
    this.header = new IcmpV4Header(builder);
  }

  @Override
  public IcmpV4Header getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  public static final class Builder {

    private IcmpV4TypeCode typeCode;
    private short checksum;
    private short identifier;
    private short sequenceNumber;
    private Packet payload;
    private boolean validateAtBuild = true;

    public Builder() {}

    public Builder(IcmpV4Packet packet) {
      this.typeCode = packet.header.typeCode;
      this.checksum = packet.header.checksum;
      this.identifier = packet.header.identifier;
      this.sequenceNumber = packet.header.sequenceNumber;
      this.payload = packet.payload;
    }

    public Builder typeCode(IcmpV4TypeCode typeCode) {
      this.typeCode = typeCode;
      return this;
    }

    public Builder checksum(short checksum) {
      this.checksum = checksum;
      return this;
    }

    public Builder identifier(short identifier) {
      this.identifier = identifier;
      return this;
    }

    public Builder sequenceNumber(short sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    public Builder payload(Packet payload) {
      this.payload = payload;
      return this;
    }

    public Builder validateAtBuild(boolean validateAtBuild) {
      this.validateAtBuild = validateAtBuild;
      return this;
    }

    public IcmpV4Packet build() {
      return new IcmpV4Packet(this);
    }

  }

  public final class IcmpV4Header extends AbstractHeader {

    private static final int TYPE_OFFSET
      = 0;
    private static final int TYPE_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int CODE_OFFSET
      = TYPE_OFFSET + TYPE_SIZE;
    private static final int CODE_SIZE
      = BYTE_SIZE_IN_BYTE;
    private static final int CHECKSUM_OFFSET
      = CODE_OFFSET + CODE_SIZE;
    private static final int CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int IDENTIFIER_OFFSET
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;
    private static final int IDENTIFIER_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int SEQUENCE_NUMBER_OFFSET
      = IDENTIFIER_OFFSET + IDENTIFIER_SIZE;
    private static final int SEQUENCE_NUMBER_SIZE
      = SHORT_SIZE_IN_BYTE;
    private static final int ICMP_HEADER_SIZE
      = SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE;

    public static final byte TYPE_ECHO_REPLY = (byte)0;
    public static final byte TYPE_DST_UNREACHABLE = (byte)3;
    public static final byte TYPE_ECHO_REQUEST = (byte)8;
    public static final byte TYPE_TIME_EXCEEDED = (byte)11;
    public static final byte CODE_ECHO_REPLY = (byte)0;
    public static final byte CODE_NETWROK_UNREACHABLE = (byte)0;
    public static final byte CODE_HOST_UNREACHABLE = (byte)1;

    private final IcmpV4TypeCode typeCode;
    private final short checksum;
    private final short identifier;
    private final short sequenceNumber;

//    private byte[] rawData = null;
//    private String stringData = null;

    private IcmpV4Header(byte[] rawData) {
      if (rawData.length < ICMP_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.typeCode
        = IcmpV4TypeCode
            .getInstance(ByteArrays.getShort(rawData, TYPE_OFFSET));
      this.checksum
        = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
      this.identifier
        = ByteArrays.getShort(rawData, IDENTIFIER_OFFSET);
      this.sequenceNumber
        = ByteArrays.getShort(rawData, SEQUENCE_NUMBER_OFFSET);
    }

    private IcmpV4Header(Builder builder) {
      this.typeCode = builder.typeCode;
      this.identifier = builder.identifier;
      this.sequenceNumber = builder.sequenceNumber;

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

      System.arraycopy(getRawData(), 0, data, 0, length());
      System.arraycopy(
        IcmpV4Packet.this.payload.getRawData(), 0,
        data, length(), IcmpV4Packet.this.payload.length()
      );

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    public IcmpV4TypeCode getTypeCode() {
      return typeCode;
    }

    public short getChecksum() {
      return checksum;
    }

    public short getIdentifier() {
      return identifier;
    }

    public int getIdentifierAsInt() {
      return (int)(0xFFFF & identifier);
    }

    public short getSequenceNumber() {
      return sequenceNumber;
    }

    public int getSequenceNumberAsInt() {
      return (int)(0xFFFF & sequenceNumber);
    }

    @Override
    public boolean isValid() {
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
    public int length() {
      return ICMP_HEADER_SIZE;
    }

    @Override
    public byte[] getRawData() {
      byte[] rawData = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray(typeCode.value()), 0,
        rawData, TYPE_OFFSET, TYPE_SIZE + CODE_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(checksum), 0,
        rawData, CHECKSUM_OFFSET, CHECKSUM_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(identifier), 0,
        rawData, IDENTIFIER_OFFSET, IDENTIFIER_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(sequenceNumber), 0,
        rawData, SEQUENCE_NUMBER_OFFSET, SEQUENCE_NUMBER_SIZE
      );

      return rawData;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();

      sb.append("[ICMP Header (")
        .append(length())
        .append(" bytes)]\n");

      sb.append("  Type,Code: ")
        .append(typeCode)
        .append("\n");

      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append("\n");

      sb.append("  Identifier: ")
        .append(getIdentifierAsInt())
        .append("\n");

      sb.append("  Sequence number: ")
        .append(getSequenceNumberAsInt())
        .append("\n");

      return sb.toString();
    }

  }

}
