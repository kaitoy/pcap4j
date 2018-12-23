/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.PppDllProtocol;
import org.pcap4j.util.ByteArrays;

/**
 * https://tools.ietf.org/html/rfc1661
 *
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public class PppPacket extends AbstractPppPacket {

  /** */
  private static final long serialVersionUID = 6735517864342242611L;

  private final PppHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new PppPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static PppPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    PppHeader header = new PppHeader(rawData, offset, length);
    return new PppPacket(rawData, offset, length, header);
  }

  private PppPacket(byte[] rawData, int offset, int length, PppHeader header)
      throws IllegalRawDataException {
    super(rawData, offset, length, header);
    this.header = header;
  }

  private PppPacket(Builder builder) {
    super(builder);
    this.header = new PppHeader(builder);
  }

  @Override
  public PppHeader getHeader() {
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

    /** */
    public Builder() {}

    private Builder(PppPacket packet) {
      super(packet);
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
    public PppPacket build() {
      return new PppPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public static class PppHeader extends AbstractPppHeader {

    /*
     * +----------+-------------+---------+
     * | Protocol | Information | Padding |
     * | 8/16 bits|      *      |    *    |
     * +----------+-------------+---------+
     */

    /** */
    private static final long serialVersionUID = -8271596051012324861L;

    private PppHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      super(rawData, offset, length);
      if (length < PPP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an PPP header(")
            .append(PPP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    }

    private PppHeader(Builder builder) {
      super(builder);
    }
  }
}
