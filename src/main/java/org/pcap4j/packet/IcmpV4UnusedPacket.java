/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
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
abstract class IcmpV4UnusedPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 7586474832634491181L;

  /**
   *
   */
  protected IcmpV4UnusedPacket() {}

  /**
   *
   * @param builder
   */
  protected IcmpV4UnusedPacket(Builder builder) {
    if (
         builder == null
      || builder.invokingPacket == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.ipV4Packet: ").append(builder.invokingPacket);
      throw new NullPointerException(sb.toString());
    }
  }

  @Override
  public abstract IcmpUnusedHeader getHeader();

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  static abstract class Builder extends AbstractBuilder {

    private int unused;
    private Packet invokingPacket;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    protected Builder(IcmpV4UnusedPacket packet) {
      this.unused = packet.getHeader().unused;
      this.invokingPacket = packet.getHeader().invokingPacket;
    }

    /**
     *
     * @param unused
     * @return
     */
    public Builder unused(int unused) {
      this.unused = unused;
      return this;
    }

    /**
     *
     * @param invokingPacket
     * @return
     */
    public Builder invokingPacket(Packet invokingPacket) {
      this.invokingPacket = invokingPacket;
      return this;
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  static abstract class IcmpUnusedHeader extends AbstractHeader {

    /*
     *   0                            15                              31
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                             unused                            |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |IPv4 Header + 64 bits of Original Data Datagram(invokingPacket)|
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 4262382112573702987L;

    private static final int UNUSED_OFFSET
      = 0;
    private static final int UNUSED_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int INVOKING_PACKET_OFFSET
      = UNUSED_OFFSET + UNUSED_SIZE;

    private final int unused;
    private final Packet invokingPacket; // Internet Header + 64 bits of Original Data Datagram

    protected IcmpUnusedHeader(byte[] rawData) {
      if (rawData.length < INVOKING_PACKET_OFFSET) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ")
          .append(getHeaderName())
          .append("(")
          .append(INVOKING_PACKET_OFFSET)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.unused
        = ByteArrays.getInt(rawData, UNUSED_OFFSET);

      Packet p = PacketFactories.getFactory(EtherType.class)
                   .newPacket(
                      ByteArrays.getSubArray(
                        rawData,
                        INVOKING_PACKET_OFFSET,
                        rawData.length - UNUSED_SIZE
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

    /**
     *
     * @param builder
     */
    protected IcmpUnusedHeader(Builder builder) {
      this.unused = builder.unused;
      this.invokingPacket = builder.invokingPacket;
    }

    /**
     *
     * @return
     */
    public int getUnused() { return unused; }

    /**
     *
     * @return
     */
    public Packet getInvokingPacket() { return invokingPacket; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(unused));
      rawFields.add(invokingPacket.getRawData());
      return rawFields;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[")
        .append(getHeaderName())
        .append(" (")
        .append(length())
        .append(" bytes)]")
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

    protected abstract String getHeaderName();

  }

}
