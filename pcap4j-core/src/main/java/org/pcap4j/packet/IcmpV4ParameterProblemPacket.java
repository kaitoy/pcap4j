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
 * @since pcap4j 0.9.11
 */
public final class IcmpV4ParameterProblemPacket extends IcmpV4InvokingPacketPacket {

  /** */
  private static final long serialVersionUID = 5369176981310492220L;

  private final IcmpV4ParameterProblemHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IcmpV4ParameterProblemPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IcmpV4ParameterProblemPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    IcmpV4ParameterProblemHeader header = new IcmpV4ParameterProblemHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      return new IcmpV4ParameterProblemPacket(
          header, rawData, offset + header.length(), payloadLength);
    } else {
      return new IcmpV4ParameterProblemPacket(header);
    }
  }

  private IcmpV4ParameterProblemPacket(IcmpV4ParameterProblemHeader header) {
    this.header = header;
  }

  private IcmpV4ParameterProblemPacket(
      IcmpV4ParameterProblemHeader header, byte[] rawData, int payloadOffset, int payloadLength) {
    super(rawData, payloadOffset, payloadLength);
    this.header = header;
  }

  private IcmpV4ParameterProblemPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4ParameterProblemHeader(builder);
  }

  @Override
  public IcmpV4ParameterProblemHeader getHeader() {
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
  public static final class Builder extends org.pcap4j.packet.IcmpV4InvokingPacketPacket.Builder {

    private byte pointer;
    private int unused;

    /** */
    public Builder() {}

    private Builder(IcmpV4ParameterProblemPacket packet) {
      super(packet);
      this.pointer = packet.header.pointer;
      this.unused = packet.header.unused;
    }

    /**
     * @param pointer pointer
     * @return this Builder object for method chaining.
     */
    public Builder pointer(byte pointer) {
      this.pointer = pointer;
      return this;
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
    public IcmpV4ParameterProblemPacket build() {
      return new IcmpV4ParameterProblemPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4ParameterProblemHeader extends AbstractHeader {

    /*
     *  0                            15                              31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Pointer    |                   unused                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 7946304491624744071L;

    private static final int POINTER_AND_UNUSED_OFFSET = 0;
    private static final int POINTER_AND_UNUSED_SIZE = INT_SIZE_IN_BYTES;
    private static final int ICMPV4_PARAMETER_PROBLEM_HEADER_SIZE =
        POINTER_AND_UNUSED_OFFSET + POINTER_AND_UNUSED_SIZE;

    private final byte pointer;
    private final int unused;

    private IcmpV4ParameterProblemHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < ICMPV4_PARAMETER_PROBLEM_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build" + " an ICMPv4 Parameter Problem Header(")
            .append(ICMPV4_PARAMETER_PROBLEM_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int pointerAndUnused = ByteArrays.getInt(rawData, POINTER_AND_UNUSED_OFFSET + offset);
      this.pointer = (byte) (pointerAndUnused >>> 24);
      this.unused = pointerAndUnused & 0x00FFFFFF;
    }

    private IcmpV4ParameterProblemHeader(Builder builder) {
      if ((builder.unused & 0xFF000000) != 0) {
        throw new IllegalArgumentException("Invalid unused: " + builder.unused);
      }

      this.pointer = builder.pointer;
      this.unused = builder.unused;
    }

    /** @return pointer */
    public byte getPointer() {
      return pointer;
    }

    /** @return pointer */
    public int getPointerAsInt() {
      return pointer & 0xFF;
    }

    /** @return unused */
    public int getUnused() {
      return unused;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(pointer << 24 | unused));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV4_PARAMETER_PROBLEM_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Parameter Problem Header (")
          .append(length())
          .append(" bytes)]")
          .append(ls);
      sb.append("  Pointer: ").append(getPointerAsInt()).append(ls);
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

      IcmpV4ParameterProblemHeader other = (IcmpV4ParameterProblemHeader) obj;
      return pointer == other.pointer && unused == other.unused;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + pointer;
      result = 31 * result + unused;
      return result;
    }
  }
}
