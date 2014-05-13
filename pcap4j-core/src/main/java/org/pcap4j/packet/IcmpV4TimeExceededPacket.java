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
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4TimeExceededPacket extends IcmpV4InvokingPacketPacket {

  /**
   *
   */
  private static final long serialVersionUID = -7403391242412189831L;

  private final IcmpV4TimeExceededHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV4TimeExceededPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IcmpV4TimeExceededPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    IcmpV4TimeExceededHeader header = new IcmpV4TimeExceededHeader(rawData);

    int payloadLength = rawData.length - header.length();
    if (payloadLength > 0) {
      byte[] rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
      return new IcmpV4TimeExceededPacket(header, rawPayload);
    }
    else {
      return new IcmpV4TimeExceededPacket(header);
    }
  }

  private IcmpV4TimeExceededPacket(IcmpV4TimeExceededHeader header) {
    this.header = header;
  }

  private IcmpV4TimeExceededPacket(IcmpV4TimeExceededHeader header, byte[] rawPayload) {
    super(rawPayload);
    this.header = header;
  }

  private IcmpV4TimeExceededPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4TimeExceededHeader(builder);
  }

  @Override
  public IcmpV4TimeExceededHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class Builder extends org.pcap4j.packet.IcmpV4InvokingPacketPacket.Builder {

    private int unused;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4TimeExceededPacket packet) {
      super(packet);
      this.unused = packet.getHeader().unused;
    }

    /**
     *
     * @param unused
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
    public IcmpV4TimeExceededPacket build() {
      return new IcmpV4TimeExceededPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4TimeExceededHeader extends AbstractHeader {

    /*
     *   0                            15                              31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                             unused                            |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = -4958423484698708497L;

    private static final int UNUSED_OFFSET
      = 0;
    private static final int UNUSED_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int ICMPV4_TIME_EXCEEDED_HEADER_SIZE
      = UNUSED_OFFSET + UNUSED_SIZE;

    private final int unused;

    private IcmpV4TimeExceededHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < ICMPV4_TIME_EXCEEDED_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 Time Exceeded Header(")
          .append(ICMPV4_TIME_EXCEEDED_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.unused
        = ByteArrays.getInt(rawData, UNUSED_OFFSET);
    }

    private IcmpV4TimeExceededHeader(Builder builder) {
      this.unused = builder.unused;
    }

    /**
     *
     * @return unused
     */
    public int getUnused() { return unused; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(unused));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV4_TIME_EXCEEDED_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Time Exceeded Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Unused: ")
        .append(unused)
        .append(ls);
      return sb.toString();
    }

  }

}
