/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.IcmpV4Helper;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4ParameterProblemPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -5827054648461879177L;

  private final IcmpV4ParameterProblemHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV4ParameterProblemPacket object
   */
  public static IcmpV4ParameterProblemPacket newPacket(byte[] rawData) {
    return new IcmpV4ParameterProblemPacket(rawData);
  }

  private IcmpV4ParameterProblemPacket(byte[] rawData) {
    this.header = new IcmpV4ParameterProblemHeader(rawData);
  }

  private IcmpV4ParameterProblemPacket(Builder builder) {
    if (
         builder == null
      || builder.invokingPacket == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.ipV4Packet: ").append(builder.invokingPacket);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV4ParameterProblemHeader(builder);
  }

  @Override
  public IcmpV4ParameterProblemHeader getHeader() { return header; }

  @Override
  public Builder getBuilder() { return new Builder(this); }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends AbstractBuilder {

    private byte pointer;
    private int unused;
    private Packet invokingPacket;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4ParameterProblemPacket packet) {
      this.pointer = packet.header.pointer;
      this.unused = packet.header.unused;
      this.invokingPacket = packet.header.invokingPacket;
    }

    /**
     *
     * @param pointer
     * @return this Builder object for method chaining.
     */
    public Builder pointer(byte pointer) {
      this.pointer = pointer;
      return this;
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

    /**
     *
     * @param invokingPacket
     * @return this Builder object for method chaining.
     */
    public Builder invokingPacket(Packet invokingPacket) {
      this.invokingPacket = invokingPacket;
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
     * |IPv4 Header + 64 bits of Original Data Datagram(invokingPacket)|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 5262923124352587894L;

    private static final int POINTER_AND_UNUSED_OFFSET
      = 0;
    private static final int POINTER_AND_UNUSED_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int INVOKING_PACKET_OFFSET
      = POINTER_AND_UNUSED_OFFSET + POINTER_AND_UNUSED_SIZE;

    private final byte pointer;
    private final int unused;
    private final Packet invokingPacket; // Internet Header + 64 bits of Original Data Datagram

    private IcmpV4ParameterProblemHeader(byte[] rawData) {
      if (rawData.length < INVOKING_PACKET_OFFSET) {
        StringBuilder sb = new StringBuilder(80);
        sb.append(
             "The data is too short to build"
               + " an ICMPv4 Parameter Problem Header("
           )
          .append(INVOKING_PACKET_OFFSET)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      int pointerAndUnused
        = ByteArrays.getInt(rawData, POINTER_AND_UNUSED_OFFSET);
      this.pointer = (byte)(pointerAndUnused >>> 24);
      this.unused = pointerAndUnused & 0x00FFFFFF;

      Packet p = PacketFactories.getFactory(EtherType.class)
                   .newPacket(
                      ByteArrays.getSubArray(
                        rawData,
                        INVOKING_PACKET_OFFSET,
                        rawData.length - POINTER_AND_UNUSED_SIZE
                      ),
                      EtherType.IPV4
                    );

      if (p instanceof IllegalPacket) {
        this.invokingPacket = p;
        return;
      }
      else if (p.contains(IllegalPacket.class)) {
        Packet.Builder builder = p.getBuilder();
        builder.getOuterOf(IllegalPacket.Builder.class)
          .payloadBuilder(
             new UnknownPacket.Builder()
               .rawData(p.get(IllegalPacket.class).getRawData())
           );
        for (Packet.Builder b: builder) {
          if (b instanceof LengthBuilder) {
            ((LengthBuilder<?>)b).correctLengthAtBuild(false);
          }
          if (b instanceof ChecksumBuilder) {
            ((ChecksumBuilder<?>)b).correctChecksumAtBuild(false);
          }
        }
        p = builder.build();
      }

      this.invokingPacket = IcmpV4Helper.makePacketForInvokingPacketField(p);
    }

    private IcmpV4ParameterProblemHeader(Builder builder) {
      if ((builder.unused & 0xFF000000) != 0) {
        throw new IllegalArgumentException("Invalid unused: " + builder.unused);
      }

      this.pointer = builder.pointer;
      this.unused = builder.unused;
      this.invokingPacket = builder.invokingPacket;
    }

    /**
     *
     * @return pointer
     */
    public byte getPointer() { return pointer; }

    /**
     *
     * @return pointer
     */
    public int getPointerAsInt() { return pointer & 0xFF; }

    /**
     *
     * @return unused
     */
    public int getUnused() { return unused; }

    /**
     *
     * @return invokingPacket
     */
    public Packet getInvokingPacket() { return invokingPacket; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(pointer << 24 | unused));
      rawFields.add(invokingPacket.getRawData());
      return rawFields;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Parameter Problem Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Pointer: ")
        .append(getPointerAsInt())
        .append(ls);
      sb.append("  Unused: ")
        .append(unused)
        .append(ls);
      sb.append("  Invoking Packet: {").append(ls)
        .append(invokingPacket)
        .append("}")
        .append(ls);

      return sb.toString();
    }

  }

}
