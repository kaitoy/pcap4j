/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class IpV6ExtUnknownPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -7055290165058067091L;

  private final IpV6ExtUnknownHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV6ExtUnknownPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6ExtUnknownPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV6ExtUnknownPacket(rawData, offset, length);
  }

  private IpV6ExtUnknownPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new IpV6ExtUnknownHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      PacketFactory<Packet, IpNumber> factory =
          PacketFactories.getFactory(Packet.class, IpNumber.class);
      Class<? extends Packet> nextPacketClass = factory.getTargetClass(header.getNextHeader());
      Packet nextPacket;
      if (nextPacketClass.equals(factory.getTargetClass())) {
        nextPacket =
            PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(
                    rawData,
                    offset + header.length(),
                    payloadLength,
                    NotApplicable.UNKNOWN_IP_V6_EXTENSION);
        if (nextPacket instanceof IllegalPacket) {
          nextPacket = factory.newInstance(rawData, offset + header.length(), payloadLength);
        }
      } else {
        nextPacket =
            PacketFactories.getFactory(Packet.class, IpNumber.class)
                .newInstance(
                    rawData, offset + header.length(), payloadLength, header.getNextHeader());
      }

      this.payload = nextPacket;
    } else {
      this.payload = null;
    }
  }

  private IpV6ExtUnknownPacket(Builder builder) {
    if (builder == null || builder.nextHeader == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextHeader: ")
          .append(builder.nextHeader)
          .append(" builder.data: ")
          .append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IpV6ExtUnknownHeader(builder);
  }

  @Override
  public IpV6ExtUnknownHeader getHeader() {
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
   * @since pcap4j 0.9.10
   */
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<IpV6ExtUnknownPacket> {

    private IpNumber nextHeader;
    private byte hdrExtLen;
    private byte[] data;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(IpV6ExtUnknownPacket packet) {
      this.nextHeader = packet.header.nextHeader;
      this.hdrExtLen = packet.header.hdrExtLen;
      this.data = packet.header.data;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param nextHeader nextHeader
     * @return this Builder object for method chaining.
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     * @param hdrExtLen hdrExtLen
     * @return this Builder object for method chaining.
     */
    public Builder hdrExtLen(byte hdrExtLen) {
      this.hdrExtLen = hdrExtLen;
      return this;
    }

    /**
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(byte[] data) {
      this.data = data;
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
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IpV6ExtUnknownPacket build() {
      return new IpV6ExtUnknownPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static final class IpV6ExtUnknownHeader extends AbstractHeader {

    /*
     *   0                              16                            31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |  Next Header  |  Hdr Ext Len  |                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
     *  |                                                               |
     *  .                                                               .
     *  .                       data                                    .
     *  .                                                               .
     *  |                                                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = -4314577591889991355L;

    private static final int NEXT_HEADER_OFFSET = 0;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HDR_EXT_LEN_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HDR_EXT_LEN_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int DATA_OFFSET = HDR_EXT_LEN_OFFSET + HDR_EXT_LEN_SIZE;

    private final IpNumber nextHeader;
    private final byte hdrExtLen;
    private final byte[] data;

    private IpV6ExtUnknownHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 4) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data length of this header is must be more than 3. data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.nextHeader =
          IpNumber.getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset));
      this.hdrExtLen = ByteArrays.getByte(rawData, HDR_EXT_LEN_OFFSET + offset);

      int headerLength = (getHdrExtLenAsInt() + 1) * 8;
      if (length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build this header(")
            .append(headerLength)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.data = ByteArrays.getSubArray(rawData, DATA_OFFSET + offset, headerLength - DATA_OFFSET);
    }

    private IpV6ExtUnknownHeader(Builder builder) {
      if (builder.data.length < 6) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("data length must be more than 5. data: ")
            .append(ByteArrays.toHexString(builder.data, " "));
        throw new IllegalArgumentException(sb.toString());
      }
      if (((builder.data.length + 2) % 8) != 0) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("(builder.data.length + 2) % 8 must be 0. data: ").append(builder.data);
        throw new IllegalArgumentException(sb.toString());
      }

      this.nextHeader = builder.nextHeader;
      this.data = ByteArrays.clone(builder.data);

      if (builder.correctLengthAtBuild) {
        this.hdrExtLen = (byte) ((data.length + 2) / 8 - 1);
      } else {
        this.hdrExtLen = builder.hdrExtLen;
      }
    }

    /** @return nextHeader */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /** @return hdrExtLen */
    public byte getHdrExtLen() {
      return hdrExtLen;
    }

    /** @return hdrExtLen */
    public int getHdrExtLenAsInt() {
      return 0xFF & hdrExtLen;
    }

    /** @return data */
    public byte[] getData() {
      return ByteArrays.clone(data);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hdrExtLen));
      rawFields.add(getData());
      return rawFields;
    }

    @Override
    public int calcLength() {
      return data.length + 2;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 Unknown Extension Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Next Header: ").append(nextHeader).append(ls);
      sb.append("  Hdr Ext Len: ")
          .append(getHdrExtLenAsInt())
          .append(" (")
          .append((getHdrExtLenAsInt() + 1) * 8)
          .append(" [bytes])")
          .append(ls);
      sb.append("  data: ").append(ByteArrays.toHexString(data, " ")).append(ls);

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

      IpV6ExtUnknownHeader other = (IpV6ExtUnknownHeader) obj;
      return nextHeader.equals(other.nextHeader)
          && hdrExtLen == other.hdrExtLen
          && Arrays.equals(data, other.data);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + nextHeader.hashCode();
      result = 31 * result + hdrExtLen;
      result = 31 * result + Arrays.hashCode(data);
      return result;
    }
  }
}
