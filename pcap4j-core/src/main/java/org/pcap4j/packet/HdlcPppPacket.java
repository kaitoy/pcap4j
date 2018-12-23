/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.pcap4j.util.ByteArrays;

/**
 * https://tools.ietf.org/html/rfc1662
 *
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public class HdlcPppPacket extends AbstractPppPacket {

  /** */
  private static final long serialVersionUID = -5976235177385846196L;

  private final HdlcPppHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new HdlcPppPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static HdlcPppPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    HdlcPppHeader header = new HdlcPppHeader(rawData, offset, length);
    return new HdlcPppPacket(rawData, offset, length, header);
  }

  private HdlcPppPacket(byte[] rawData, int offset, int length, HdlcPppHeader header)
      throws IllegalRawDataException {
    super(rawData, offset, length, header);
    this.header = header;
  }

  private HdlcPppPacket(Builder builder) {
    super(builder);
    this.header = new HdlcPppHeader(builder);
  }

  @Override
  public HdlcPppHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public static class Builder extends AbstractPppPacket.Builder {

    private byte address = (byte) 0xFF;
    private byte control = (byte) 0x03;

    /** */
    public Builder() {}

    private Builder(HdlcPppPacket packet) {
      super(packet);
      this.address = packet.header.address;
      this.control = packet.header.control;
    }

    /**
     * @param address 0xFF by default. Don't change it to comply with the protocol.
     * @return this Builder object for method chaining.
     */
    public Builder address(byte address) {
      this.address = address;
      return this;
    }

    /**
     * @param control 0x03 by default. Don't change it to comply with the protocol.
     * @return this Builder object for method chaining.
     */
    public Builder control(byte control) {
      this.control = control;
      return this;
    }

    @Override
    public Builder protocol(PppDllProtocol protocol) {
      super.protocol(protocol);
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      super.payloadBuilder(payloadBuilder);
      return this;
    }

    @Override
    public Builder pad(byte[] pad) {
      super.pad(pad);
      return this;
    }

    @Override
    public HdlcPppPacket build() {
      return new HdlcPppPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public static class HdlcPppHeader extends AbstractPppHeader {

    /*
     * +----------+----------+----------+
     * |   Flag   | Address  | Control  |
     * | 01111110 | 11111111 | 00000011 |
     * +----------+----------+----------+
     * +----------+-------------+---------+
     * | Protocol | Information | Padding |
     * | 8/16 bits|      *      |    *    |
     * +----------+-------------+---------+
     * +----------+----------+-----------------
     * |   FCS    |   Flag   | Inter-frame Fill
     * |16/32 bits| 01111110 | or next Address
     * +----------+----------+-----------------
     *
     * Pcap library captures from Address to Padding.
     * It seemds the rest are handled by NIF.
     *
     */

    /** */
    private static final long serialVersionUID = -6084002362363168427L;

    private static final int ADDRESS_OFFSET = 0;
    private static final int ADDRESS_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CONTROL_OFFSET = ADDRESS_OFFSET + ADDRESS_SIZE;
    private static final int CONTROL_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int PPP_HEADER_OFFSET = CONTROL_OFFSET + CONTROL_SIZE;
    private static final int HDLC_PPP_HEADER_SIZE = PPP_HEADER_OFFSET + PPP_HEADER_SIZE;

    private final byte address;
    private final byte control;

    private HdlcPppHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      super(rawData, offset + PPP_HEADER_OFFSET, length - PPP_HEADER_OFFSET);

      if (length < HDLC_PPP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an HDLC PPP header(")
            .append(HDLC_PPP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.address = ByteArrays.getByte(rawData, ADDRESS_OFFSET + offset);
      this.control = ByteArrays.getByte(rawData, CONTROL_OFFSET + offset);
    }

    private HdlcPppHeader(Builder builder) {
      super(builder);
      this.address = builder.address;
      this.control = builder.control;
    }

    /** @return address */
    public byte getAddress() {
      return address;
    }

    /** @return control */
    public byte getControl() {
      return control;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(address));
      rawFields.add(ByteArrays.toByteArray(control));
      rawFields.add(ByteArrays.toByteArray(getProtocol().value()));
      return rawFields;
    }

    @Override
    public int length() {
      return HDLC_PPP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[HDLC-encapsulated PPP Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Address: 0x").append(String.format("%02x", address)).append(ls);
      sb.append("  Control: 0x").append(String.format("%02x", control)).append(ls);
      sb.append("  Protocol: ").append(getProtocol()).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (!super.equals(obj)) {
        return false;
      }

      HdlcPppHeader other = (HdlcPppHeader) obj;
      return address == other.address && control == other.control;
    }

    @Override
    protected int calcHashCode() {
      int result = super.calcHashCode();
      result = 31 * result + address;
      result = 31 * result + control;
      return result;
    }
  }
}
