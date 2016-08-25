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

import org.pcap4j.packet.namednumber.GtpV1MessageType;
import org.pcap4j.util.ByteArrays;

/**
 * GTPv1 Packet.
 *
 * @see <a href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI TS 129 060 V12.6.0</a>
 * @author Waveform
 * @since pcap4j 1.6.6
 */
public final class GtpV1Packet extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4638029542367352625L;

  private final GtpHeader header;
  private final Packet payload;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new GtpV1Packet object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static GtpV1Packet newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpV1Packet(rawData, offset, length);
  }

  private GtpV1Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new GtpHeader(rawData, offset, length);

    int payloadLength = header.getLengthAsInt() - header.length();
    if (payloadLength < 0) {
      throw new IllegalRawDataException(
              "The value of length field seems to be wrong: "
                + header.getLengthAsInt()
            );
    }

    if (payloadLength > length - header.length()) {
      payloadLength = length - header.length();
    }

    if (payloadLength != 0) {
      this.payload = null;
    }
    else {
      this.payload = null;
    }
  }

  private GtpV1Packet(Builder builder) {
    if (
      builder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);

      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new GtpHeader(
                    builder,
                    payload != null ? payload.getRawData() : new byte[0]
                  );
  }

  @Override
  public GtpHeader getHeader() {
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
   * @author Waveform
   * @since pcap4j 1.6.6
   */
  public static final class Builder extends AbstractBuilder implements LengthBuilder<GtpV1Packet> {

    private GtpVersion version;
    private boolean protocolType;
    private boolean reserved;
    private boolean sequenceNumberFlag;
    private boolean extensionHeaderFlag;
    private boolean nPduNumberFlag;
    private GtpV1MessageType messageType;
    private short length;
    private int teid;
    private Short sequenceNumber;
    private Byte nPduNumber;
    private Byte nextExtensionHeaderType;
    private boolean correctLengthAtBuild;
    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet packet
     */
    public Builder(GtpV1Packet packet) {
      this.protocolType = packet.header.protocolType;
      this.version = packet.header.version;
      this.reserved = packet.header.reserved;
      this.length = packet.header.length;
      this.messageType= packet.header.messageType;
      this.nPduNumberFlag = packet.header.nPduNumberFlag;
      this.sequenceNumber = packet.header.sequenceNumber;
      this.nPduNumber = packet.header.nPduNumber;
      this.nextExtensionHeaderType = packet.header.nextExtensionHeaderType;
      this.sequenceNumberFlag = packet.header.sequenceNumberFlag;
      this.teid = packet.header.teid;
      this.extensionHeaderFlag = packet.header.extensionHeaderFlag;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param protocolType protocolType
     * @return this Builder object for method chaining.
     */
    public Builder protocolType(boolean protocolType) {
      this.protocolType = protocolType;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(boolean reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(short length) {
      this.length = length;
      return this;
    }

    /**
     * @param extensionHeaderFlag extensionHeaderFlag
     * @return this Builder object for method chaining.
     */
    public Builder extensionHeaderFlag(boolean extensionHeaderFlag) {
      this.extensionHeaderFlag = extensionHeaderFlag;
      return this;
    }

    /**
     * @param sequenceNumberFlag sequenceNumberFlag
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumberFlag(boolean sequenceNumberFlag) {
      this.sequenceNumberFlag = sequenceNumberFlag;
      return this;
    }

    /**
     * @param nPduNumberFlag nPduNumberFlag
     * @return this Builder object for method chaining.
     */
    public Builder nPduNumberFlag(boolean nPduNumberFlag) {
      this.nPduNumberFlag = nPduNumberFlag;
      return this;
    }

    /**
     * @param messageType messageType
     * @return this Builder object for method chaining.
     */
    public Builder messageType(GtpV1MessageType messageType) {
      this.messageType = messageType;
      return this;
    }

    /**
     * @param teid teid
     * @return this Builder object for method chaining.
     */
    public Builder teid(int teid) {
      this.teid = teid;
      return this;
    }

    /**
     * @param sequenceNumber sequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(short sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    /**
     * @param nPduNumber nPduNumber
     * @return this Builder object for method chaining.
     */
    public Builder nPduNumber(byte nPduNumber) {
      this.nPduNumber= nPduNumber;
      return this;
    }

    /**
     * @param nextExtensionHeaderType nextExtensionHeaderType
     * @return this Builder object for method chaining.
     */
    public Builder nextExtensionHeaderType(byte nextExtensionHeaderType) {
      this.nextExtensionHeaderType = nextExtensionHeaderType;
      return this;
    }

    /**
     *
     * @param version version
     * @return this Builder object for method chaining.
     */
    public Builder version(GtpVersion version) {
      this.version = version;
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
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public GtpV1Packet build() {
      return new GtpV1Packet(this);
    }

  }

  /**
   * GTPv1 Header
   *
   * <pre style="white-space: pre;">
   *   8     7     6     5     4     3     2     1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Version    |  PT  | (*) |  E  |  S  |  PN  |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                 Message Type                  |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |              Length (1st Octet)               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |              Length (2nd Octet)               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Tunnel Endpoint Identifier (1st Octet)     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Tunnel Endpoint Identifier (2nd Octet)     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Tunnel Endpoint Identifier (3rd Octet)     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Tunnel Endpoint Identifier (4th Octet)     |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |          Sequence Number (1st Octet)          |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |          Sequence Number (2nd Octet)          |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                 N-PDU Number                  |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |          Next Extension Header Type           |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * </pre>
   *
   * @see <a href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI TS 129 060 V12.6.0</a>
   * @author Waveform
   * @since pcap4j 1.6.6
   */
  public static final class GtpHeader extends AbstractHeader {

    /**
     *
     */
    private static final long serialVersionUID = -1746545325551976324L;

    private static final int FIRST_OCTET_OFFSET
      = 0;
    private static final int FIRST_OCTET_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int MSG_TYPE_OFFSET
      = FIRST_OCTET_OFFSET + FIRST_OCTET_SIZE;
    private static final int MSG_TYPE_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET
      = MSG_TYPE_OFFSET + MSG_TYPE_SIZE;
    private static final int LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TUNNEL_ID_OFFSET
      = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int TUNNEL_ID_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int SEQ_OFFSET
      = TUNNEL_ID_OFFSET + TUNNEL_ID_SIZE;
    private static final int SEQ_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int NPDU_OFFSET
      = SEQ_OFFSET + SEQ_SIZE;
    private static final int NPDU_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int NEXT_HEADER_OFFSET
      = NPDU_OFFSET + NPDU_SIZE;
    private static final int NEXT_HEADER_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int GTP_HEADER_SIZE
      = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;

    private final GtpVersion version;
    private final boolean protocolType;
    private final boolean reserved;
    private final boolean extensionHeaderFlag;
    private final boolean sequenceNumberFlag;
    private final boolean nPduNumberFlag;
    private final GtpV1MessageType messageType;
    private final short length;
    private final int teid;
    private final Short sequenceNumber;
    private final Byte nPduNumber;
    private final Byte nextExtensionHeaderType;

    private GtpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < GTP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a GTP header(")
          .append(GTP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      byte firstOctet = ByteArrays.getByte(rawData, FIRST_OCTET_OFFSET + offset);
      this.version = GtpVersion.getInstance((firstOctet >> 5) & 0x07);
      this.protocolType = (firstOctet & 0x10) != 0;
      this.reserved = ((firstOctet & 0x08) >> 3) != 0;
      this.extensionHeaderFlag = ((firstOctet & 0x04) >> 2) != 0;
      this.sequenceNumberFlag = ((firstOctet & 0x02) >> 1) != 0;
      this.nPduNumberFlag = (firstOctet & 0x01)!=0;

      this.messageType
        = GtpV1MessageType.getInstance(ByteArrays.getByte(rawData, MSG_TYPE_OFFSET + offset));

      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);

      this.teid = ByteArrays.getInt(rawData, TUNNEL_ID_OFFSET + offset);

      this.sequenceNumber = ByteArrays.getShort(rawData, SEQ_OFFSET + offset);

      this.nPduNumber = ByteArrays.getByte(rawData, NPDU_OFFSET + offset);

      this.nextExtensionHeaderType = ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset);
    }

    private GtpHeader(Builder builder, byte[] payload) {
      this.protocolType = builder.protocolType;
      this.version = builder.version;
      this.reserved = builder.reserved;
      this.messageType= builder.messageType;
      this.nPduNumberFlag = builder.nPduNumberFlag;
      this.sequenceNumber = builder.sequenceNumber;
      this.nPduNumber = builder.nPduNumber;
      this.nextExtensionHeaderType = builder.nextExtensionHeaderType;
      this.sequenceNumberFlag = builder.sequenceNumberFlag;
      this.teid = builder.teid;
      this.extensionHeaderFlag = builder.extensionHeaderFlag;

      if (builder.correctLengthAtBuild) {
        this.length = (short)((payload.length + getLength()));
      }
      else {
        this.length = builder.length;
      }
    }

    /**
     *
     * @return version
     */
    public GtpVersion getversion() {
      return version;
    }

    /**
     * @return true if the Protocol Type field is set to 1 (GTP); false otherwise (GTP').
     */
    public boolean getProtocolType() {
      return protocolType;
    }

    /**
     * @return true if the reserved field is set to 1; false otherwise.
     */
    public boolean getReserved() {
      return reserved;
    }

    /**
     * @return true if the extension header flag is set to 1; false otherwise.
     */
    public boolean isExtensionHeaderFieldPresent() {
      return extensionHeaderFlag;
    }

    /**
     * @return true if the sequence number flag is set to 1; false otherwise.
     */
    public boolean isSequenceNumberFieldPresent() {
      return sequenceNumberFlag;
    }

    /**
     * @return true if the N-PDU number flag is set to 1; false otherwise.
     */
    public boolean isNPduNumberFieldPresent() {
      return nPduNumberFlag;
    }

    /**
     *
     * @return messageType
     */
    public GtpV1MessageType getMessageType() {
      return messageType;
    }

    /**
     * @return length
     */
    public short getLength() {
      return length;
    }

    /**
     *
     * @return length
     */
    public int getLengthAsInt() {
      return 0xFFFF & length;
    }

    /**
     * @return teid
     */
    public int getTeid() {
      return teid;
    }

    /**
     * @return teid
     */
    public long getTeidAsLong() {
      return teid & 0xFFFFFFFFL;
    }

    /**
     * @return sequenceNumber. May be null.
     */
    public Short getSequenceNumber() {
      return sequenceNumber;
    }

    /**
     * @return sequenceNumber. May be null.
     */
    public Integer getSequenceNumberAsInt() {
      if (sequenceNumber == null) {
        return null;
      }
      else {
        return sequenceNumber & 0xFFFF;
      }
    }

    /**
     * @return nPduNumber. May be null.
     */
    public Byte getNPduNumber() {
      return nPduNumber;
    }

    /**
     * @return nPduNumber. May be null.
     */
    public Integer getNPduNumberAsInt() {
      if (nPduNumber == null) {
        return null;
      }
      else {
        return nPduNumber & 0xFF;
      }
    }

    /**
     * @return nextExtensionHeaderType. May be null.
     */
    public Byte getNextExtensionHeaderType() {
      return nextExtensionHeaderType;
    }

    @Override
    protected List<byte[]> getRawFields() {
      byte flags = (byte) (version.getValue() << 5);
      if (protocolType) { flags |= 0x10; }
      if (reserved) { flags = (byte) (flags | 0x08); }
      if (extensionHeaderFlag) { flags =(byte) (flags | 0x04); }
      if (sequenceNumberFlag) { flags = (byte) (flags | 0x02); }
      if (nPduNumberFlag) { flags = (byte) (flags | 0x01); }
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(flags));
      rawFields.add(ByteArrays.toByteArray(messageType.value()));
      rawFields.add(ByteArrays.toByteArray(length));
      rawFields.add(ByteArrays.toByteArray(teid));
      rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      rawFields.add(ByteArrays.toByteArray(nPduNumber));
      rawFields.add(ByteArrays.toByteArray(nextExtensionHeaderType));
      return rawFields;
    }

    @Override
    public int length() {
      return GTP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[GTPv1 Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Version: ")
        .append(version)
        .append(ls);
      sb.append("  Protocol Type: ")
        .append(protocolType ? "GTP" : "GTP'")
        .append(ls);
      sb.append("  Reserved Flag: ")
        .append(reserved)
        .append(ls);
      sb.append("  Extension Flag: ")
        .append(extensionHeaderFlag)
        .append(ls);
      sb.append("  Sequence Flag: ")
        .append(sequenceNumberFlag)
        .append(ls);
      sb.append("  NPDU Flag: ")
        .append(nPduNumberFlag)
        .append(ls);
      sb.append("  Message Type: ")
        .append(messageType)
        .append(ls);
      sb.append("  Length: ")
        .append(getLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Tunnel ID: ")
        .append(getTeidAsLong())
        .append(ls);
      if (sequenceNumber != null) {
        sb.append("  Sequence Number: ")
          .append(getSequenceNumberAsInt())
          .append(ls);
      }
      if (nPduNumber != null) {
        sb.append("  NPDU Number: ")
          .append(getNPduNumberAsInt())
          .append(ls);
      }
      if (nextExtensionHeaderType != null) {
        sb.append("  Next Extension Header: ")
          .append(getNextExtensionHeaderType())
          .append(ls);
      }

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }

      GtpHeader other = (GtpHeader)obj;
      return
           length == other.length
        && version == other.version
        && protocolType == other.protocolType
        && reserved == other.reserved
        && extensionHeaderFlag == other.extensionHeaderFlag
        && sequenceNumberFlag == other.sequenceNumberFlag
        && nPduNumberFlag == other.nPduNumberFlag
        && messageType == other.messageType
        && teid == other.teid
        && sequenceNumber == other.sequenceNumber
        && nPduNumber == other.nPduNumber
        && nextExtensionHeaderType == other.nextExtensionHeaderType;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + version.hashCode();
      result = 31 * result + (protocolType ? 1231 : 1237);
      result = 31 * result + (reserved ? 1231 : 1237);
      result = 31 * result + (extensionHeaderFlag ? 1231 : 1237);
      result = 31 * result + (sequenceNumberFlag ? 1231 : 1237);
      result = 31 * result + (nPduNumberFlag ? 1231 : 1237);
      result = 31 * result + messageType.hashCode();
      result = 31 * result + sequenceNumber;
      result = 31 * result + nPduNumber;
      result = 31 * result + nextExtensionHeaderType;
      result = 31 * result + length;
      return result;
    }

  }

}
