/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4InformationRequestPacket extends IcmpIdentifiablePacket {

  /**
   *
   */
  private static final long serialVersionUID = 840757374756962085L;

  private final IcmpV4InformationRequestHeader header;

  /**
   *
   * @param rawData
   * @return a new IcmpV4InformationRequestPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IcmpV4InformationRequestPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IcmpV4InformationRequestPacket(rawData);
  }

  private IcmpV4InformationRequestPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new IcmpV4InformationRequestHeader(rawData);
  }

  private IcmpV4InformationRequestPacket(Builder builder) {
    super(builder);
    this.header = new IcmpV4InformationRequestHeader(builder);
  }

  @Override
  public IcmpV4InformationRequestHeader getHeader() { return header; }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static
  final class Builder extends org.pcap4j.packet.IcmpIdentifiablePacket.Builder {

    /**
     *
     */
    public Builder() {}

    private Builder(IcmpV4InformationRequestPacket packet) { super(packet); }

    @Override
    public Builder identifier(short identifier) {
      super.identifier(identifier);
      return this;
    }

    @Override
    public Builder sequenceNumber(short sequenceNumber) {
      super.sequenceNumber(sequenceNumber);
      return this;
    }

    @Override
    public IcmpV4InformationRequestPacket build() {
      return new IcmpV4InformationRequestPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class IcmpV4InformationRequestHeader extends IcmpIdentifiableHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /**
     *
     */
    private static final long serialVersionUID = 5499456155277110739L;

    private IcmpV4InformationRequestHeader(byte[] rawData) throws IllegalRawDataException {
      super(rawData);
    }

    private IcmpV4InformationRequestHeader(Builder builder) { super(builder); }

    @Override
    protected String getHeaderName() {
      return "ICMPv4 Information Request Header";
    }

  }

}
