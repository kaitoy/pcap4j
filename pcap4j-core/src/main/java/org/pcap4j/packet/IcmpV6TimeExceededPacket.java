/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6TimeExceededPacket extends IcmpV6InvokingPacketPacket {

  /** */
  private static final long serialVersionUID = 548806622487019458L;

  private final IcmpV6TimeExceededHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV6TimeExceededPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV6TimeExceededPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    IcmpV6TimeExceededHeader header = new IcmpV6TimeExceededHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      return new IcmpV6TimeExceededPacket(header, rawData, offset + header.length(), payloadLength);
    } else {
      return new IcmpV6TimeExceededPacket(header);
    }
  }

  private IcmpV6TimeExceededPacket(IcmpV6TimeExceededHeader header) {
    this.header = header;
  }

  private IcmpV6TimeExceededPacket(
      IcmpV6TimeExceededHeader header, byte[] rawData, int payloadOffset, int payloadLength) {
    super(rawData, payloadOffset, payloadLength);
    this.header = header;
  }

  private IcmpV6TimeExceededPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV6TimeExceededHeader(builder);
  }

  @Override
  public IcmpV6TimeExceededHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class Builder extends org.pcap4j.packet.IcmpV6InvokingPacketPacket.Builder {

    private int unused;

    /** */
    public Builder() {}

    private Builder(IcmpV6TimeExceededPacket packet) {
      super(packet);
      this.unused = packet.getHeader().unused;
    }

    /**
     * @param unused unused
     * @return this Builder object for method chaining.
     */
    public Builder unused(int unused) {
      this.unused = unused;
      return this;
    }

    @Override
    public Builder payload(Packet payload) {
      super.payload(payload);
      return this;
    }

    @Override
    public IcmpV6TimeExceededPacket build() {
      return new IcmpV6TimeExceededPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.15
   */
  public static final class IcmpV6TimeExceededHeader extends AbstractHeader {

    /*
     *   0                            15                              31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                             unused                            |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 7744561095455514341L;

    private static final int UNUSED_OFFSET = 0;
    private static final int UNUSED_SIZE = INT_SIZE_IN_BYTES;
    private static final int ICMPV6_TIME_EXCEEDED_HEADER_SIZE = UNUSED_OFFSET + UNUSED_SIZE;

    private final int unused;

    private IcmpV6TimeExceededHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < ICMPV6_TIME_EXCEEDED_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv6 Time Exceeded Header(")
            .append(ICMPV6_TIME_EXCEEDED_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.unused = ByteArrays.getInt(rawData, UNUSED_OFFSET + offset);
    }

    private IcmpV6TimeExceededHeader(Builder builder) {
      this.unused = builder.unused;
    }

    /** @return unused */
    public int getUnused() {
      return unused;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(unused));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV6_TIME_EXCEEDED_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv6 Time Exceeded Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Unused: ").append(unused).append(ls);
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

      IcmpV6TimeExceededHeader other = (IcmpV6TimeExceededHeader) obj;
      return unused == other.unused;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + unused;
      return result;
    }
  }
}
