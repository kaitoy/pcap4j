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

public class IcmpV4Packet extends AbstractPacket implements L4Packet {

  private IcmpHeader header;
  private Packet payload;

  public IcmpV4Packet() {
    this.header = new IcmpHeader();
    this.payload = null;
  }

  public IcmpV4Packet(byte[] rawData) {
    this.header = new IcmpHeader(rawData);

    this.payload
      = new AnonymousPacket(
          ByteArrays.getSubArray(
            rawData,
            IcmpHeader.ICMP_HEADER_SIZE,
            rawData.length - IcmpHeader.ICMP_HEADER_SIZE
          )
        );
  }

  @Override
  public IcmpHeader getHeader() {
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

  public class IcmpHeader extends AbstractHeader {

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

    private IcmpV4TypeCode typeCode;
    private short checksum;
    private short identifier;
    private short sequenceNumber;

    private IcmpHeader() {}

    private IcmpHeader(byte[] rawHeader) {
      if (rawHeader.length < ICMP_HEADER_SIZE) {
        throw new IllegalArgumentException();
      }

      this.typeCode
        = IcmpV4TypeCode
            .getInstance(ByteArrays.getShort(rawHeader, TYPE_OFFSET));
      this.checksum
        = ByteArrays.getShort(rawHeader, CHECKSUM_OFFSET);
      this.identifier
        = ByteArrays.getShort(rawHeader, IDENTIFIER_OFFSET);
      this.sequenceNumber
        = ByteArrays.getShort(rawHeader, SEQUENCE_NUMBER_OFFSET);
    }

    public IcmpV4TypeCode getTypeCode() {
      return typeCode;
    }

    public void setTypeCode(IcmpV4TypeCode typeCode) {
      this.typeCode = typeCode;
    }

    public short getChecksum() {
      return checksum;
    }

    public void setChecksum(short checksum) {
      this.checksum = checksum;
    }

    public short getIdentifier() {
      return identifier;
    }

    public int getIdentifierAsInt() {
      return (int)(0xFFFF & identifier);
    }

    public void setIdentifier(short identifier) {
      this.identifier = identifier;
    }

    public short getSequenceNumber() {
      return sequenceNumber;
    }

    public int getSequenceNumberAsInt() {
      return (int)(0xFFFF & sequenceNumber);
    }

    public void setSequenceNumber(short sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
    }

    @Override
    public void validate() {
      if (
        PacketPropertiesLoader.getInstance()
          .isEnableIcmpChecksumVaridation()
      ) {
        setChecksum(calcChecksum());
      }
      else {
        setChecksum((short)0);
      }
    }

    private short calcChecksum() {
      byte[] data;

      int packetLength = IcmpV4Packet.this.length();
      if ((packetLength % 2) != 0) {
        data = new byte[packetLength + 1];
        System.arraycopy(IcmpV4Packet.this.getRawData(), 0, data, 0, packetLength);
        data[packetLength] = (byte)0;
      }
      else {
        data = IcmpV4Packet.this.getRawData();
      }

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    @Override
    public boolean isValid() {
      if (
        PacketPropertiesLoader.getInstance()
          .isEnableIcmpChecksumVerification()
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
      byte[] data = new byte[length()];
      System.arraycopy(
        ByteArrays.toByteArray(typeCode.value()), 0,
        data, TYPE_OFFSET, TYPE_SIZE + CODE_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(checksum), 0,
        data, CHECKSUM_OFFSET, CHECKSUM_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(identifier), 0,
        data, IDENTIFIER_OFFSET, IDENTIFIER_SIZE
      );
      System.arraycopy(
        ByteArrays.toByteArray(sequenceNumber), 0,
        data, SEQUENCE_NUMBER_OFFSET, SEQUENCE_NUMBER_SIZE
      );
      return data;
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
