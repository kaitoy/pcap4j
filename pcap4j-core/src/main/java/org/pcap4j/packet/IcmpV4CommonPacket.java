/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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

  /**
   *
   */
  private static final long serialVersionUID = 7643067752830062365L;

  private final IcmpV4CommonHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IcmpV4CommonPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IcmpV4CommonPacket newPacket(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IcmpV4CommonPacket(rawData);
  }

  private IcmpV4CommonPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV4CommonHeader(rawData);

    int payloadLength = rawData.length - header.length();
    if (payloadLength > 0) {
      byte[] rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
      this.payload
        = PacketFactories.getFactory(Packet.class, IcmpV4Type.class)
            .newInstance(rawPayload, header.getType());
    }
    else {
      this.payload = null;
    }
  }

  private IcmpV4CommonPacket(Builder builder) {
    if (
         builder == null
      || builder.type == null
      || builder.code == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.type: ").append(builder.type)
        .append(" builder.code: ").append(builder.code);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IcmpV4CommonHeader(
                    builder,
                    payload != null ? payload.getRawData() : new byte[0]
                  );
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
   *
   * @param acceptZero
   * @return true if the packet represented by this object has a valid checksum;
   *         false otherwise.
   */
  public boolean hasValidChecksum(boolean acceptZero) {
    if (header.checksum == 0) {
      if (acceptZero) { return true; }
      else { return false; }
    }

    if (payload != null) {
      return header.calcChecksum(payload.getRawData()) == header.checksum;
    }
    else {
      return header.calcChecksum(new byte[0]) == header.checksum;
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final
  class Builder extends AbstractBuilder
  implements ChecksumBuilder<IcmpV4CommonPacket> {

    private IcmpV4Type type;
    private IcmpV4Code code;
    private short checksum;
    private Packet.Builder payloadBuilder;
    private boolean correctChecksumAtBuild;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4CommonPacket packet) {
      this.type = packet.header.type;
      this.code = packet.header.code;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     *
     * @param type
     * @return this Builder object for method chaining.
     */
    public Builder type(IcmpV4Type type) {
      this.type = type;
      return this;
    }

    /**
     *
     * @param code
     * @return this Builder object for method chaining.
     */
    public Builder code(IcmpV4Code code) {
      this.code = code;
      return this;
    }

    /**
     *
     * @param checksum
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

    /**
     *
     */
    private static final long serialVersionUID = 504881105187659087L;

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
    private static final int ICMPV4_COMMON_HEADER_SIZE
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private final IcmpV4Type type;
    private final IcmpV4Code code;
    private final short checksum;

    private IcmpV4CommonHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < ICMPV4_COMMON_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 common header(")
          .append(ICMPV4_COMMON_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.type
        = IcmpV4Type
            .getInstance(ByteArrays.getByte(rawData, TYPE_OFFSET));
      this.code
        = IcmpV4Code
            .getInstance(type.value(), ByteArrays.getByte(rawData, CODE_OFFSET));
      this.checksum
        = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
    }

    private IcmpV4CommonHeader(Builder builder, byte[] payload) {
      this.type = builder.type;
      this.code = builder.code;

      if (builder.correctChecksumAtBuild) {
        if (PacketPropertiesLoader.getInstance().icmpV4CalcChecksum()) {
          this.checksum = calcChecksum(payload);
        }
        else {
          this.checksum = (short)0;
        }
      }
      else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(byte[] payload) {
      byte[] data;
      int packetLength = payload.length + length();

      if ((packetLength % 2) != 0) {
        data = new byte[packetLength + 1];
      }
      else {
        data = new byte[packetLength];
      }

      // If call getRawData() here, rawData will be cached with
      // an invalid checksum in some cases.
      // To avoid it, use buildRawData() instead.
      System.arraycopy(buildRawData(), 0, data, 0, length());

      System.arraycopy(
        payload, 0, data, length(), payload.length
      );

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return type
     */
    public IcmpV4Type getType() {
      return type;
    }

    /**
     *
     * @return code
     */
    public IcmpV4Code getCode() {
      return code;
    }

    /**
     *
     * @return checksum
     */
    public short getChecksum() {
      return checksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(type.value()));
      rawFields.add(ByteArrays.toByteArray(code.value()));
      rawFields.add(ByteArrays.toByteArray(checksum));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV4_COMMON_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Common Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Type: ")
        .append(type)
        .append(ls);
      sb.append("  Code: ")
        .append(code)
        .append(ls);
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append(ls);

      return sb.toString();
    }

  }

}
