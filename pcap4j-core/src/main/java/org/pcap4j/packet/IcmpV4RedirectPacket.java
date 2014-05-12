/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4RedirectPacket extends IcmpV4InvokingPacketPacket {

  /**
   *
   */
  private static final long serialVersionUID = 5987521162450318499L;

  private final IcmpV4RedirectHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV4RedirectPacket object.
   * @throws IllegalRawDataException
   */
  public static IcmpV4RedirectPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    IcmpV4RedirectHeader header = new IcmpV4RedirectHeader(rawData);

    int payloadLength = rawData.length - header.length();
    if (payloadLength > 0) {
      byte[] rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
      return new IcmpV4RedirectPacket(header, rawPayload);
    }
    else {
      return new IcmpV4RedirectPacket(header, null);
    }
  }

  private IcmpV4RedirectPacket(IcmpV4RedirectHeader header, byte[] rawPayload) {
    super(rawPayload);
    this.header = header;
  }

  private IcmpV4RedirectPacket(Builder builder) {
    super(builder);

    if (builder.gatewayInternetAddress == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder.gatewayInternetAddress: ")
        .append(builder.gatewayInternetAddress);
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
  public static final class Builder
  extends org.pcap4j.packet.IcmpV4InvokingPacketPacket.Builder {

    private Inet4Address gatewayInternetAddress;

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4RedirectPacket packet) {
      super(packet);
      this.gatewayInternetAddress = packet.header.gatewayInternetAddress;
    }

    /**
     *
     * @param gatewayInternetAddress
     * @return this Builder object for method chaining.
     */
    public Builder gatewayInternetAddress(Inet4Address gatewayInternetAddress) {
      this.gatewayInternetAddress = gatewayInternetAddress;
      return this;
    }

    @Override
    public Builder payload(Packet payload) {
      super.payload(payload);
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
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = -7093717116891501880L;

    private static final int GATEWAY_INTERNET_ADDRESS_OFFSET
      = 0;
    private static final int GATEWAY_INTERNET_ADDRESS_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int ICMPV4_REDIRECT_HEADER_SIZE
      = GATEWAY_INTERNET_ADDRESS_OFFSET + GATEWAY_INTERNET_ADDRESS_SIZE;

    private final Inet4Address gatewayInternetAddress;

    private IcmpV4RedirectHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < ICMPV4_REDIRECT_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ICMPv4 Redirect Header(")
          .append(ICMPV4_REDIRECT_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.gatewayInternetAddress
        = ByteArrays.getInet4Address(rawData, GATEWAY_INTERNET_ADDRESS_OFFSET);
   }

    private IcmpV4RedirectHeader(Builder builder) {
      this.gatewayInternetAddress = builder.gatewayInternetAddress;
    }

    /**
     *
     * @return gatewayInternetAddress
     */
    public Inet4Address getGatewayInternetAddress() {
      return gatewayInternetAddress;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(gatewayInternetAddress));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMPV4_REDIRECT_HEADER_SIZE;
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

      return sb.toString();
    }

  }

}
