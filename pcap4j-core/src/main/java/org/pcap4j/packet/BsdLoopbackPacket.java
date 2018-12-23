/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.ProtocolFamily;
import org.pcap4j.util.ByteArrays;

/**
 * @see <a href="http://www.tcpdump.org/linktypes.html">Description of DLT_NULL in a Tcpdump
 *     document</a>
 * @author Kaito Yamada
 * @since pcap4j 1.5.0
 */
public final class BsdLoopbackPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 5348192606048946251L;

  private final BsdLoopbackHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new BsdLoopbackPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static BsdLoopbackPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new BsdLoopbackPacket(rawData, offset, length);
  }

  private BsdLoopbackPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new BsdLoopbackHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, ProtocolFamily.class)
              .newInstance(
                  rawData, offset + header.length(), payloadLength, header.getProtocolFamily());
    } else {
      this.payload = null;
    }
  }

  private BsdLoopbackPacket(Builder builder) {
    if (builder == null || builder.protocolFamily == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.packetType: ")
          .append(builder.protocolFamily);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new BsdLoopbackHeader(builder);
  }

  @Override
  public BsdLoopbackHeader getHeader() {
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
   * @since pcap4j 1.5.0
   */
  public static final class Builder extends AbstractBuilder {

    private ProtocolFamily protocolFamily;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    private Builder(BsdLoopbackPacket packet) {
      this.protocolFamily = packet.header.protocolFamily;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param protocolFamily protocolFamily
     * @return this Builder object for method chaining.
     */
    public Builder protocolFamily(ProtocolFamily protocolFamily) {
      this.protocolFamily = protocolFamily;
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
    public BsdLoopbackPacket build() {
      return new BsdLoopbackPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.5.0
   */
  public static final class BsdLoopbackHeader extends AbstractHeader {

    /*
     * BSD loopback encapsulation; the link layer header is a 4-byte field,
     * in host byte order, containing a PF_ value from socket.h for the
     * network-layer protocol of the packet.
     * Note that ``host byte order'' is the byte order of the machine
     * on which the packets are captured, and the PF_ values are for the
     * OS of the machine on which the packets are captured; if a live capture
     * is being done, ``host byte order'' is the byte order of the machine
     * capturing the packets, and the PF_ values are those of the OS of the
     * machine capturing the packets, but if a ``savefile'' is being read,
     * the byte order and PF_ values are not necessarily those of the
     * machine reading the capture file.
     */

    /** */
    private static final long serialVersionUID = -1053845855337317937L;

    private static final int PROTOCOL_FAMILY_OFFSET = 0;
    private static final int PROTOCOL_FAMILY_SIZE = INT_SIZE_IN_BYTES;
    private static final int BSD_LOOPBACK_HEADER_SIZE =
        PROTOCOL_FAMILY_OFFSET + PROTOCOL_FAMILY_SIZE;

    private final ProtocolFamily protocolFamily;

    private BsdLoopbackHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < BSD_LOOPBACK_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a BSD loopback header(")
            .append(BSD_LOOPBACK_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.protocolFamily =
          ProtocolFamily.getInstance(
              ByteArrays.getInt(rawData, PROTOCOL_FAMILY_OFFSET + offset, ByteOrder.nativeOrder()));
    }

    private BsdLoopbackHeader(Builder builder) {
      this.protocolFamily = builder.protocolFamily;
    }

    /** @return protocolFamily */
    public ProtocolFamily getProtocolFamily() {
      return protocolFamily;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(protocolFamily.value(), ByteOrder.nativeOrder()));
      return rawFields;
    }

    @Override
    public int length() {
      return BSD_LOOPBACK_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[BSD Loopback Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Protocol Family: ").append(protocolFamily).append(ls);

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

      BsdLoopbackHeader other = (BsdLoopbackHeader) obj;
      return protocolFamily.equals(other.protocolFamily);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + protocolFamily.hashCode();
      return result;
    }
  }
}
