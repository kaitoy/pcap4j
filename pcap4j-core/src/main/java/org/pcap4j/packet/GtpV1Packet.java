/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.GtpV1MessageType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * GTPv1 Packet.
 *
 * @see <a
 *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
 *     TS 129 060 V12.6.0</a>
 * @author Waveform
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class GtpV1Packet extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 4638029542367352625L;

  private final GtpV1Header header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new GtpV1Packet object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static GtpV1Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpV1Packet(rawData, offset, length);
  }

  private GtpV1Packet(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new GtpV1Header(rawData, offset, length);

    int payloadLength = header.getLengthAsInt();
    if (header.isExtensionHeaderFieldPresent()
        || header.isSequenceNumberFieldPresent()
        || header.isNPduNumberFieldPresent()) {
      payloadLength -= 4;
    }

    if (header.isExtensionHeaderFieldPresent()) {
      for (GtpV1ExtensionHeader gtpV1ExtensionHeader : header.extensionHeaders) {
        payloadLength -= gtpV1ExtensionHeader.length();
      }
    }

    if (payloadLength < 0) {
      throw new IllegalRawDataException(
          "The value of length field seems to be wrong: " + header.getLengthAsInt());
    }

    if (payloadLength != 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, NotApplicable.class)
              .newInstance(rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
    } else {
      this.payload = null;
    }
  }

  private GtpV1Packet(Builder builder) {
    if (builder == null
        || builder.version == null
        || builder.protocolType == null
        || builder.messageType == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(", builder.version: ")
          .append(builder.version)
          .append(", builder.protocolType: ")
          .append(builder.protocolType)
          .append(", builder.messageType: ")
          .append(builder.messageType);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new GtpV1Header(builder, payload != null ? payload.length() : 0);
  }

  @Override
  public GtpV1Header getHeader() {
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
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static final class Builder extends AbstractBuilder implements LengthBuilder<GtpV1Packet> {

    private GtpVersion version;
    private ProtocolType protocolType;
    private boolean reserved;
    private boolean sequenceNumberFlag;
    private boolean extensionHeaderFlag;
    private boolean nPduNumberFlag;
    private GtpV1MessageType messageType;
    private short length;
    private int teid;
    private Short sequenceNumber;
    private Byte nPduNumber;
    private GtpV1ExtensionHeaderType nextExtensionHeaderType;
    private List<GtpV1ExtensionHeader> gtpV1ExtensionHeaders;
    private boolean correctLengthAtBuild;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(GtpV1Packet packet) {
      this.protocolType = packet.header.protocolType;
      this.version = packet.header.version;
      this.reserved = packet.header.reserved;
      this.length = packet.header.length;
      this.messageType = packet.header.messageType;
      this.nPduNumberFlag = packet.header.nPduNumberFlag;
      this.sequenceNumber = packet.header.sequenceNumber;
      this.nPduNumber = packet.header.nPduNumber;
      this.nextExtensionHeaderType = packet.header.nextExtensionHeaderType;
      this.sequenceNumberFlag = packet.header.sequenceNumberFlag;
      this.teid = packet.header.teid;
      this.extensionHeaderFlag = packet.header.extensionHeaderFlag;
      this.gtpV1ExtensionHeaders = packet.header.extensionHeaders;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param protocolType protocolType
     * @return this Builder object for method chaining.
     */
    public Builder protocolType(ProtocolType protocolType) {
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
      this.nPduNumber = nPduNumber;
      return this;
    }

    /**
     * @param nextExtensionHeaderType nextExtensionHeaderType
     * @return this Builder object for method chaining.
     */
    public Builder nextExtensionHeaderType(GtpV1ExtensionHeaderType nextExtensionHeaderType) {
      this.nextExtensionHeaderType = nextExtensionHeaderType;
      return this;
    }

    /**
     * @param gtpV1ExtensionHeaders gtpV1ExtensionHeaders
     * @return this Builder object for method chaining.
     */
    public Builder gtpV1ExtensionHeaders(List<GtpV1ExtensionHeader> gtpV1ExtensionHeaders) {
      this.gtpV1ExtensionHeaders = gtpV1ExtensionHeaders;
      return this;
    }

    /**
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
   *    8     7     6     5     4     3     2     1
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |    Version      | PT  | (*) |  E  |  S  | PN  |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |                 Message Type                  |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |              Length (1st Octet)               |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |              Length (2nd Octet)               |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |    Tunnel Endpoint Identifier (1st Octet)     |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |    Tunnel Endpoint Identifier (2nd Octet)     |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |    Tunnel Endpoint Identifier (3rd Octet)     |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |    Tunnel Endpoint Identifier (4th Octet)     |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |          Sequence Number (1st Octet)          |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |          Sequence Number (2nd Octet)          |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |                 N-PDU Number                  |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |          Next Extension Header Type           |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * </pre>
   *
   * @see <a
   *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
   *     TS 129 060 V12.6.0</a>
   * @author Waveform
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static final class GtpV1Header extends AbstractHeader {

    /** */
    private static final long serialVersionUID = -1746545325551976324L;

    private static final int FIRST_OCTET_OFFSET = 0;
    private static final int FIRST_OCTET_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int MSG_TYPE_OFFSET = FIRST_OCTET_OFFSET + FIRST_OCTET_SIZE;
    private static final int MSG_TYPE_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET = MSG_TYPE_OFFSET + MSG_TYPE_SIZE;
    private static final int LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int TUNNEL_ID_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int TUNNEL_ID_SIZE = INT_SIZE_IN_BYTES;
    private static final int GTP_V1_HEADER_MIN_SIZE = TUNNEL_ID_OFFSET + TUNNEL_ID_SIZE;
    private static final int SEQ_OFFSET = TUNNEL_ID_OFFSET + TUNNEL_ID_SIZE;
    private static final int SEQ_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int NPDU_OFFSET = SEQ_OFFSET + SEQ_SIZE;
    private static final int NPDU_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int NEXT_HEADER_OFFSET = NPDU_OFFSET + NPDU_SIZE;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int EXTENSION_HEADER_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;

    private final GtpVersion version;
    private final ProtocolType protocolType;
    private final boolean reserved;
    private final boolean extensionHeaderFlag;
    private final boolean sequenceNumberFlag;
    private final boolean nPduNumberFlag;
    private final GtpV1MessageType messageType;
    private final short length;
    private final int teid;
    private final Short sequenceNumber;
    private final Byte nPduNumber;
    private final GtpV1ExtensionHeaderType nextExtensionHeaderType;
    private final List<GtpV1ExtensionHeader> extensionHeaders;

    private GtpV1Header(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < GTP_V1_HEADER_MIN_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a GTPv1 header(")
            .append(GTP_V1_HEADER_MIN_SIZE)
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
      this.protocolType = ProtocolType.getInstance((firstOctet & 0x10) != 0);
      this.reserved = ((firstOctet & 0x08) >> 3) != 0;
      this.extensionHeaderFlag = ((firstOctet & 0x04) >> 2) != 0;
      this.sequenceNumberFlag = ((firstOctet & 0x02) >> 1) != 0;
      this.nPduNumberFlag = (firstOctet & 0x01) != 0;
      this.messageType =
          GtpV1MessageType.getInstance(ByteArrays.getByte(rawData, MSG_TYPE_OFFSET + offset));
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);
      this.teid = ByteArrays.getInt(rawData, TUNNEL_ID_OFFSET + offset);

      extensionHeaders = new ArrayList<>();
      if (sequenceNumberFlag || nPduNumberFlag || extensionHeaderFlag) {
        if (length < EXTENSION_HEADER_OFFSET) {
          StringBuilder sb = new StringBuilder(80);
          sb.append("The data is too short to build a GTPv1 header(")
              .append(EXTENSION_HEADER_OFFSET)
              .append(" bytes). data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length);
          throw new IllegalRawDataException(sb.toString());
        }

        this.sequenceNumber = ByteArrays.getShort(rawData, SEQ_OFFSET + offset);
        this.nPduNumber = ByteArrays.getByte(rawData, NPDU_OFFSET + offset);
        this.nextExtensionHeaderType =
            GtpV1ExtensionHeaderType.getInstance(rawData[NEXT_HEADER_OFFSET + offset]);
        GtpV1ExtensionHeaderType curExtensionHeaderType = this.nextExtensionHeaderType;
        int curLength = length - EXTENSION_HEADER_OFFSET;
        int curOffset = offset + EXTENSION_HEADER_OFFSET;

        if (extensionHeaderFlag) {
          while (!curExtensionHeaderType.equals(
              GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS)) {
            GtpV1ExtensionHeader extension =
                PacketFactories.getFactory(
                        GtpV1ExtensionHeader.class, GtpV1ExtensionHeaderType.class)
                    .newInstance(rawData, curOffset, curLength, curExtensionHeaderType);

            extensionHeaders.add(extension);
            curLength -= extension.length();
            curOffset += extension.length();
            curExtensionHeaderType = extension.getNextExtensionHeaderType();
          }
        }
      } else {
        this.sequenceNumber = null;
        this.nPduNumber = null;
        this.nextExtensionHeaderType = null;
      }
    }

    private GtpV1Header(Builder builder, int payloadLen) {
      this.protocolType = builder.protocolType;
      this.version = builder.version;
      this.reserved = builder.reserved;
      this.messageType = builder.messageType;
      this.nPduNumberFlag = builder.nPduNumberFlag;
      this.sequenceNumberFlag = builder.sequenceNumberFlag;
      this.teid = builder.teid;
      this.extensionHeaderFlag = builder.extensionHeaderFlag;

      if (extensionHeaderFlag || sequenceNumberFlag || nPduNumberFlag) {
        this.sequenceNumber =
            builder.sequenceNumber == null ? new Short("0") : builder.sequenceNumber;
        this.nPduNumber = builder.nPduNumber == null ? new Byte("0") : builder.nPduNumber;
        this.nextExtensionHeaderType =
            builder.nextExtensionHeaderType == null
                ? GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS
                : builder.nextExtensionHeaderType;
      } else {
        this.sequenceNumber = builder.sequenceNumber;
        this.nPduNumber = builder.nPduNumber;
        this.nextExtensionHeaderType = builder.nextExtensionHeaderType;
      }

      if (extensionHeaderFlag) {
        this.extensionHeaders = builder.gtpV1ExtensionHeaders;
      } else {
        this.extensionHeaders = Collections.EMPTY_LIST;
      }

      if (builder.correctLengthAtBuild) {
        if (extensionHeaderFlag) {
          int extensionHeaderLength = 0;
          for (GtpV1ExtensionHeader extensionHeader : extensionHeaders) {
            extensionHeaderLength += extensionHeader.length();
          }
          this.length = (short) (payloadLen + 4 + extensionHeaderLength);
        } else if (sequenceNumberFlag || nPduNumberFlag) {
          this.length = (short) (payloadLen + 4);
        } else {
          this.length = (short) payloadLen;
        }
      } else {
        this.length = builder.length;
      }
    }

    /** @return version */
    public GtpVersion getVersion() {
      return version;
    }

    /** @return protocolType. */
    public ProtocolType getProtocolType() {
      return protocolType;
    }

    /** @return true if the reserved field is set to 1; false otherwise. */
    public boolean getReserved() {
      return reserved;
    }

    /** @return true if the extension header flag is set to 1; false otherwise. */
    public boolean isExtensionHeaderFieldPresent() {
      return extensionHeaderFlag;
    }

    /** @return true if the sequence number flag is set to 1; false otherwise. */
    public boolean isSequenceNumberFieldPresent() {
      return sequenceNumberFlag;
    }

    /** @return true if the N-PDU number flag is set to 1; false otherwise. */
    public boolean isNPduNumberFieldPresent() {
      return nPduNumberFlag;
    }

    /** @return messageType */
    public GtpV1MessageType getMessageType() {
      return messageType;
    }

    /** @return length */
    public short getLength() {
      return length;
    }

    /** @return length */
    public int getLengthAsInt() {
      return 0xFFFF & length;
    }

    /** @return teid */
    public int getTeid() {
      return teid;
    }

    /** @return teid */
    public long getTeidAsLong() {
      return teid & 0xFFFFFFFFL;
    }

    /** @return sequenceNumber. May be null. */
    public Short getSequenceNumber() {
      return sequenceNumber;
    }

    /** @return sequenceNumber. May be null. */
    public Integer getSequenceNumberAsInt() {
      if (sequenceNumber == null) {
        return null;
      } else {
        return sequenceNumber & 0xFFFF;
      }
    }

    /** @return nPduNumber. May be null. */
    public Byte getNPduNumber() {
      return nPduNumber;
    }

    /** @return nPduNumber. May be null. */
    public Integer getNPduNumberAsInt() {
      if (nPduNumber == null) {
        return null;
      } else {
        return nPduNumber & 0xFF;
      }
    }

    /** @return nextExtensionHeaderType. May be null. */
    public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
      return nextExtensionHeaderType;
    }

    /** @return extensionHeaders. May be null. */
    public List<GtpV1ExtensionHeader> getExtensionHeaders() {
      return extensionHeaders;
    }

    @Override
    protected List<byte[]> getRawFields() {
      byte flags = (byte) (version.getValue() << 5);
      if (protocolType.getValue()) {
        flags |= 0x10;
      }
      if (reserved) {
        flags |= 0x08;
      }
      if (extensionHeaderFlag) {
        flags |= 0x04;
      }
      if (sequenceNumberFlag) {
        flags |= 0x02;
      }
      if (nPduNumberFlag) {
        flags |= 0x01;
      }
      List<byte[]> rawFields = new ArrayList<>();
      rawFields.add(ByteArrays.toByteArray(flags));
      rawFields.add(ByteArrays.toByteArray(messageType.value()));
      rawFields.add(ByteArrays.toByteArray(length));
      rawFields.add(ByteArrays.toByteArray(teid));
      if (sequenceNumber != null) {
        rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      }
      if (nPduNumber != null) {
        rawFields.add(ByteArrays.toByteArray(nPduNumber));
      }
      if (nextExtensionHeaderType != null) {
        rawFields.add(ByteArrays.toByteArray(nextExtensionHeaderType.value()));
      }
      if (extensionHeaderFlag) {
        for (GtpV1ExtensionHeader extensionHeader : extensionHeaders) {
          rawFields.add(extensionHeader.getRawData());
        }
      }
      return rawFields;
    }

    @Override
    protected int calcLength() {
      int len = GTP_V1_HEADER_MIN_SIZE;
      if (sequenceNumber != null) {
        len += SHORT_SIZE_IN_BYTES;
      }
      if (nPduNumber != null) {
        len += BYTE_SIZE_IN_BYTES;
      }
      if (nextExtensionHeaderType != null) {
        len += BYTE_SIZE_IN_BYTES;
      }
      if (extensionHeaderFlag) {
        for (GtpV1ExtensionHeader extensionHeader : extensionHeaders) {
          len += extensionHeader.length();
        }
      }

      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[GTPv1 Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Version: ").append(version).append(ls);
      sb.append("  Protocol Type: ").append(protocolType).append(ls);
      sb.append("  Reserved Flag: ").append(reserved).append(ls);
      sb.append("  Extension Flag: ").append(extensionHeaderFlag).append(ls);
      sb.append("  Sequence Flag: ").append(sequenceNumberFlag).append(ls);
      sb.append("  NPDU Flag: ").append(nPduNumberFlag).append(ls);
      sb.append("  Message Type: ").append(messageType).append(ls);
      sb.append("  Length: ").append(getLengthAsInt()).append(" [bytes]").append(ls);
      sb.append("  Tunnel ID: ").append(getTeidAsLong()).append(ls);
      if (sequenceNumber != null) {
        sb.append("  Sequence Number: ").append(getSequenceNumberAsInt()).append(ls);
      }
      if (nPduNumber != null) {
        sb.append("  NPDU Number: ").append(getNPduNumberAsInt()).append(ls);
      }
      if (nextExtensionHeaderType != null) {
        sb.append("  Next Extension Header Type: ").append(getNextExtensionHeaderType()).append(ls);
      }
      if (extensionHeaders != null) {
        for (GtpV1ExtensionHeader extensionHeader : extensionHeaders) {
          sb.append(extensionHeader).append(ls);
        }
      }
      sb.delete(sb.lastIndexOf(ls), sb.length());
      return sb.toString();
    }

    @Override
    protected int calcHashCode() {
      final int prime = 31;
      int result = 17;
      result = prime * result + (extensionHeaderFlag ? 1231 : 1237);
      result = prime * result + length;
      result = prime * result + messageType.hashCode();
      result = prime * result + (nPduNumber == null ? 0 : nPduNumber.hashCode());
      result = prime * result + (nPduNumberFlag ? 1231 : 1237);
      result =
          prime * result
              + (nextExtensionHeaderType == null ? 0 : nextExtensionHeaderType.hashCode());
      result = prime * result + protocolType.hashCode();
      result = prime * result + (reserved ? 1231 : 1237);
      result = prime * result + (sequenceNumber == null ? 0 : sequenceNumber.hashCode());
      result = prime * result + (sequenceNumberFlag ? 1231 : 1237);
      result = prime * result + teid;
      result = prime * result + version.hashCode();
      result = prime * result + (extensionHeaders == null ? 0 : extensionHeaders.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      if (!super.equals(o)) {
        return false;
      }
      GtpV1Header that = (GtpV1Header) o;
      if (extensionHeaders.size() != that.extensionHeaders.size()) {
        return false;
      }

      for (int i = 0; i < extensionHeaders.size(); ++i) {
        if (!Objects.equals(extensionHeaders.get(i), that.extensionHeaders.get(i))) {
          return false;
        }
      }

      return reserved == that.reserved
          && extensionHeaderFlag == that.extensionHeaderFlag
          && sequenceNumberFlag == that.sequenceNumberFlag
          && nPduNumberFlag == that.nPduNumberFlag
          && length == that.length
          && teid == that.teid
          && version == that.version
          && protocolType == that.protocolType
          && Objects.equals(messageType, that.messageType)
          && Objects.equals(sequenceNumber, that.sequenceNumber)
          && Objects.equals(nPduNumber, that.nPduNumber)
          && Objects.equals(nextExtensionHeaderType, that.nextExtensionHeaderType);
    }
  }

  /** GtpV1 Extension Header */
  public interface GtpV1ExtensionHeader extends Serializable {

    /** @return type */
    public GtpV1ExtensionHeaderType getNextExtensionHeaderType();

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }

  /**
   * GTP Protocol Type
   *
   * @see <a
   *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
   *     TS 129 060 V12.6.0</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public enum ProtocolType {

    /** GTP': false */
    GTP_PRIME(false),

    /** GTP: true */
    GTP(true);

    private final boolean value;

    private ProtocolType(boolean value) {
      this.value = value;
    }

    /**
     * @param value value
     * @return a ProtocolType object.
     */
    public static ProtocolType getInstance(boolean value) {
      for (ProtocolType ver : values()) {
        if (ver.value == value) {
          return ver;
        }
      }
      throw new IllegalArgumentException("Invalid value: " + value);
    }

    /** @return true if GTP; false otherwise (GTP'). */
    public boolean getValue() {
      return value;
    }

    @Override
    public String toString() {
      return value ? "GTP" : "GTP'";
    }
  }
}
