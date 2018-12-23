/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4CommonPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 7643067752830062365L;

  private final IcmpV4CommonHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV4CommonPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV4CommonPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IcmpV4CommonPacket(rawData, offset, length);
  }

  private IcmpV4CommonPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IcmpV4CommonHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, IcmpV4Type.class)
              .newInstance(rawData, offset + header.length(), payloadLength, header.getType());
    } else {
      this.payload = null;
    }
  }

  private IcmpV4CommonPacket(Builder builder) {
    if (builder == null || builder.type == null || builder.code == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.type: ")
          .append(builder.type)
          .append(" builder.code: ")
          .append(builder.code);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header =
        new IcmpV4CommonHeader(builder, payload != null ? payload.getRawData() : new byte[0]);
  }

  @Override
  public IcmpV4CommonHeader getHeader() {
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
   * @param acceptZero acceptZero
   * @return true if the packet represented by this object has a valid checksum; false otherwise.
   */
  public boolean hasValidChecksum(boolean acceptZero) {
    byte[] payloadData = payload != null ? payload.getRawData() : new byte[0];
    short calculatedChecksum = header.calcChecksum(header.getRawData(), payloadData);
    if (calculatedChecksum == 0) {
      return true;
    }

    if (header.checksum == 0 && acceptZero) {
      return true;
    }

    return false;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends AbstractBuilder
      implements ChecksumBuilder<IcmpV4CommonPacket> {

    private IcmpV4Type type;
    private IcmpV4Code code;
    private short checksum;
    private Packet.Builder payloadBuilder;
    private boolean correctChecksumAtBuild;

    /** */
    public Builder() {}

    private Builder(IcmpV4CommonPacket packet) {
      this.type = packet.header.type;
      this.code = packet.header.code;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(IcmpV4Type type) {
      this.type = type;
      return this;
    }

    /**
     * @param code code
     * @return this Builder object for method chaining.
     */
    public Builder code(IcmpV4Code code) {
      this.code = code;
      return this;
    }

    /**
     * @param checksum checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(short checksum) {
      this.checksum = checksum;
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
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    @Override
    public IcmpV4CommonPacket build() {
      return new IcmpV4CommonPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4CommonHeader extends AbstractHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      Type     |     Code      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Checksum              |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 504881105187659087L;

    private static final int TYPE_OFFSET = 0;
    private static final int TYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CODE_OFFSET = TYPE_OFFSET + TYPE_SIZE;
    private static final int CODE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET = CODE_OFFSET + CODE_SIZE;
    private static final int CHECKSUM_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ICMPV4_COMMON_HEADER_SIZE = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private final IcmpV4Type type;
    private final IcmpV4Code code;
    private final short checksum;

    private IcmpV4CommonHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < ICMPV4_COMMON_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 common header(")
            .append(ICMPV4_COMMON_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.type = IcmpV4Type.getInstance(ByteArrays.getByte(rawData, TYPE_OFFSET + offset));
      this.code =
          IcmpV4Code.getInstance(type.value(), ByteArrays.getByte(rawData, CODE_OFFSET + offset));
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET + offset);
    }

    private IcmpV4CommonHeader(Builder builder, byte[] payload) {
      this.type = builder.type;
      this.code = builder.code;

      if (builder.correctChecksumAtBuild) {
        if (PacketPropertiesLoader.getInstance().icmpV4CalcChecksum()) {
          this.checksum = calcChecksum(buildRawData(true), payload);
        } else {
          this.checksum = (short) 0;
        }
      } else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(byte[] header, byte[] payload) {
      byte[] data;
      int packetLength = payload.length + length();

      if ((packetLength % 2) != 0) {
        data = new byte[packetLength + 1];
      } else {
        data = new byte[packetLength];
      }

      System.arraycopy(header, 0, data, 0, header.length);
      System.arraycopy(payload, 0, data, header.length, payload.length);

      return ByteArrays.calcChecksum(data);
    }

    /** @return type */
    public IcmpV4Type getType() {
      return type;
    }

    /** @return code */
    public IcmpV4Code getCode() {
      return code;
    }

    /** @return checksum */
    public short getChecksum() {
      return checksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      return getRawFields(false);
    }

    private List<byte[]> getRawFields(boolean zeroInsteadOfChecksum) {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(type.value()));
      rawFields.add(ByteArrays.toByteArray(code.value()));
      rawFields.add(ByteArrays.toByteArray(zeroInsteadOfChecksum ? (short) 0 : checksum));
      return rawFields;
    }

    private byte[] buildRawData(boolean zeroInsteadOfChecksum) {
      return ByteArrays.concatenate(getRawFields(zeroInsteadOfChecksum));
    }

    @Override
    public int length() {
      return ICMPV4_COMMON_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Common Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Type: ").append(type).append(ls);
      sb.append("  Code: ").append(code).append(ls);
      sb.append("  Checksum: 0x").append(ByteArrays.toHexString(checksum, "")).append(ls);

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

      IcmpV4CommonHeader other = (IcmpV4CommonHeader) obj;
      return checksum == other.checksum && type.equals(other.type) && code.equals(other.code);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + type.hashCode();
      result = 31 * result + code.hashCode();
      result = 31 * result + checksum;
      return result;
    }
  }
}
