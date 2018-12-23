/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.Oui;
import org.pcap4j.util.ByteArrays;

/**
 * SNAP (Subnetwork Access Protocol) Packet
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.html">IEEE 802</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class SnapPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 2957315717350800697L;

  private final SnapHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new SnapPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static SnapPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new SnapPacket(rawData, offset, length);
  }

  private SnapPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new SnapHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, EtherType.class)
              .newInstance(
                  rawData, offset + header.length(), payloadLength, header.getProtocolId());
    } else {
      this.payload = null;
    }
  }

  private SnapPacket(Builder builder) {
    if (builder == null || builder.oui == null || builder.protocolId == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.oui: ")
          .append(builder.oui)
          .append(" builder.protocolId: ")
          .append(builder.protocolId);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new SnapHeader(builder);
  }

  @Override
  public SnapHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder extends AbstractBuilder {

    private Oui oui;
    private EtherType protocolId;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    private Builder(SnapPacket packet) {
      this.oui = packet.header.oui;
      this.protocolId = packet.header.protocolId;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param oui oui
     * @return this Builder object for method chaining.
     */
    public Builder oui(Oui oui) {
      this.oui = oui;
      return this;
    }

    /**
     * @param protocolId protocolId
     * @return this Builder object for method chaining.
     */
    public Builder protocolId(EtherType protocolId) {
      this.protocolId = protocolId;
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    @Override
    public Packet.Builder getPayloadBuilder() {
      return payloadBuilder;
    }

    @Override
    public SnapPacket build() {
      return new SnapPacket(this);
    }
  }

  /**
   * SNAP (Subnetwork Access Protocol) Header
   *
   * <pre>{@code
   *   0                           7
   * +---+---+---+---+---+---+---+---+
   * |                               |
   * +                               +
   * |            OUI                |
   * +                               +
   * |                               |
   * +---+---+---+---+---+---+---+---+
   * |                               |
   * +        Protocol ID            +
   * |                               |
   * +---+---+---+---+---+---+---+---+
   * }</pre>
   *
   * @see <a href="http://standards.ieee.org/about/get/802/802.html">IEEE 802</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class SnapHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = 8525438913079396866L;

    private static final int OUI_OFFSET = 0;
    private static final int OUI_SIZE = 3;
    private static final int PROTOCOL_ID_OFFSET = OUI_OFFSET + OUI_SIZE;
    private static final int PROTOCOL_ID_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SNAP_HEADER_SIZE = PROTOCOL_ID_OFFSET + PROTOCOL_ID_SIZE;

    private final Oui oui;
    private final EtherType protocolId;

    private SnapHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < SNAP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a SNAP header(")
            .append(SNAP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.oui = Oui.getInstance(ByteArrays.getSubArray(rawData, offset + OUI_OFFSET, 3));
      this.protocolId =
          EtherType.getInstance(ByteArrays.getShort(rawData, offset + PROTOCOL_ID_OFFSET));
    }

    private SnapHeader(Builder builder) {
      this.oui = builder.oui;
      this.protocolId = builder.protocolId;
    }

    /** @return oui */
    public Oui getOui() {
      return oui;
    }

    /** @return protocolId */
    public EtherType getProtocolId() {
      return protocolId;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(oui.valueAsByteArray());
      rawFields.add(ByteArrays.toByteArray(protocolId.value()));
      return rawFields;
    }

    @Override
    public int length() {
      return SNAP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Subnetwork Access Protocol header (")
          .append(length())
          .append(" bytes)]")
          .append(ls);
      sb.append("  OUI: ").append(oui).append(ls);
      sb.append("  Protocol ID: ").append(protocolId).append(ls);

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

      SnapHeader other = (SnapHeader) obj;
      return oui.equals(other.oui) && protocolId.equals(other.protocolId);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + oui.hashCode();
      result = 31 * result + protocolId.hashCode();
      return result;
    }
  }
}
