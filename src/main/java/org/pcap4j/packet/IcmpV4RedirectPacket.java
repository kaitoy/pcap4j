/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;
import java.net.Inet4Address;
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
public final class IcmpV4RedirectPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 6444855719417675899L;

  private final IcmpV4RedirectHeader header;

  /**
   *
   * @param rawData
   * @return
   */
  public static IcmpV4RedirectPacket newPacket(byte[] rawData) {
    return new IcmpV4RedirectPacket(rawData);
  }

  private IcmpV4RedirectPacket(byte[] rawData) {
    this.header = new IcmpV4RedirectHeader(rawData);
  }

  private IcmpV4RedirectPacket(Builder builder) {
    if (
         builder == null
      || builder.gatewayInternetAddress == null
      || builder.invokingPacket == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.ipV4Packet: ").append(builder.invokingPacket);
      throw new NullPointerException(sb.toString());
    }

    this.header = new IcmpV4RedirectHeader(builder);
  }

  @Override
  public IcmpV4RedirectHeader getHeader() {
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
  public static final class Builder extends AbstractBuilder {

    private Inet4Address gatewayInternetAddress;
    private Packet invokingPacket;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4RedirectPacket packet) {
      this.gatewayInternetAddress = packet.header.gatewayInternetAddress;
      this.invokingPacket = packet.header.invokingPacket;
    }

    /**
     *
     * @param gatewayInternetAddress
     * @return
     */
    public Builder gatewayInternetAddress(Inet4Address gatewayInternetAddress) {
      this.gatewayInternetAddress = gatewayInternetAddress;
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

    @Override
    public IcmpV4RedirectPacket build() {
      return new IcmpV4RedirectPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4RedirectHeader extends AbstractHeader {

    /*
     *  0                            15                              31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                 Gateway Internet Address                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |IPv4 Header + 64 bits of Original Data Datagram(invokingPacket)|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */


    /**
     *
     */
    private static final long serialVersionUID = -46332865818101803L;

    private static final int GATEWAY_INTERNET_ADDRESS_OFFSET
      = 0;
    private static final int GATEWAY_INTERNET_ADDRESS_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int INVOKING_PACKET_OFFSET
      = GATEWAY_INTERNET_ADDRESS_OFFSET + GATEWAY_INTERNET_ADDRESS_SIZE;

    private final Inet4Address gatewayInternetAddress;
    private final Packet invokingPacket; // Internet Header + 64 bits of Original Data Datagram

    private IcmpV4RedirectHeader(byte[] rawData) {
      if (rawData.length < INVOKING_PACKET_OFFSET) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 Redirect Header(")
          .append(INVOKING_PACKET_OFFSET)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.gatewayInternetAddress
        = ByteArrays.getInet4Address(rawData, GATEWAY_INTERNET_ADDRESS_OFFSET);

      Packet p = PacketFactories.getFactory(EtherType.class)
                   .newPacket(
                      ByteArrays.getSubArray(
                        rawData,
                        INVOKING_PACKET_OFFSET,
                        rawData.length - GATEWAY_INTERNET_ADDRESS_SIZE
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

    private IcmpV4RedirectHeader(Builder builder) {
      this.gatewayInternetAddress = builder.gatewayInternetAddress;
      this.invokingPacket = builder.invokingPacket;
    }

    /**
     *
     * @return
     */
    public Inet4Address getGatewayInternetAddress() {
      return gatewayInternetAddress;
    }

    /**
     *
     * @return
     */
    public Packet getInvokingPacket() { return invokingPacket; }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(gatewayInternetAddress));
      rawFields.add(invokingPacket.getRawData());
      return rawFields;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[ICMPv4 Redirect Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Gateway Internet Address: ")
        .append(gatewayInternetAddress)
        .append(ls);
      sb.append("  Invoking Packet: {").append(ls)
        .append(invokingPacket)
        .append("}")
        .append(ls);

      return sb.toString();
    }

  }

}
