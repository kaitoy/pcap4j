/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.GtpV1Packet.GtpV1ExtensionHeader;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.util.ByteArrays;

/**
 * PDI Session Container GTP Extension Header which carry PDU session information
 *
 * @see <a href=
 *     "https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/15.04.00_60/ts_129281v150400p.pdf">ETSI
 *     TS 129 281 V15.4.0(2018-09)</a>
 *     <pre style="white-space: pre;">
 * d8     7     6     5     4     3     2     1
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |            Extension Header Length            |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |             PDU Session Container             |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |         Next Extenstion Header Type           |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 *  </pre>
 *     The PDU session container has a variable length and its content is specified in
 * @see <a href=
 *     "https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.01.00_60/ts_138415v150100p.pdf">ETSI
 *     TS 138 415 V15.1.0(2018-09)</a>
 *     <p>DL PDU Session Information frames PDU Type=0 and PPP is false
 *     <pre style="white-space: pre;">
 * 8     7     6     5     4     3     2     1
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |       PDU Type(=0)    |         Spare         |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * | PPP | RQI |        QoS Flow Identifier        |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * </pre>
 *     PDU Type=0 and PPP is true
 *     <pre style="white-space: pre;">
 * 8     7     6     5     4     3     2     1
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |       PDU Type(=0)    |         Spare         |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * | PPP | RQI |        QoS Flow Identifier        |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |          PPI    |         Spare               |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |                    Padding                    |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |                    Padding                    |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |                    Padding                    |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * </pre>
 *     UL PDU Session Information frames PDU Type=1
 *     <pre style="white-space: pre;">
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |       PDU Type(=1)    |         Spare         |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |   Spare   |        QoS Flow Identifier        |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * </pre>
 *
 * @author Leo Ma
 * @since pcap4j 1.7.7
 */
public class GtpV1PduSessionContainerExtensionHeader implements GtpV1ExtensionHeader {

  private static final long serialVersionUID = 7361463927403478495L;

  private static final int LENGTH_OFFSET = 0;
  private static final int LENGTH_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
  private static final int PDU_TYPE_AND_SPARE_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
  private static final int PDU_TYPE_AND_SPARE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;

  /** DL PDU SESSION INFORMATION (PDU Type 0) */
  /** Common fields */
  private static final int PPP_AND_RQI_AND_QFI_OFFSET =
      PDU_TYPE_AND_SPARE_OFFSET + PDU_TYPE_AND_SPARE_SIZE;

  private static final int PPP_AND_RQI_AND_QFI_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;

  /** PPI field(presene in case PPP is true) */
  private static final int PPI_AND_SPARE_OFFSET =
      PPP_AND_RQI_AND_QFI_OFFSET
          + PPP_AND_RQI_AND_QFI_SIZE; // should be exist only when PDU Type=0 and PPP flag is true.

  private static final int PPI_AND_SPARE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
  private static final int PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_OFFSET =
      PPI_AND_SPARE_OFFSET
          + PPI_AND_SPARE_SIZE; // should be exist only when PDU Type=0 and PPP flag is true.
  private static final int PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_SIZE =
      ByteArrays.INT_SIZE_IN_BYTES;

  /** UL PDU SESSION INFORMATION (PUD Type 1) */
  private static final int SPARE_AND_QFI_OFFSET =
      PDU_TYPE_AND_SPARE_OFFSET + PDU_TYPE_AND_SPARE_SIZE;

  private static final int NEXT_EXTENSION_HEADER_TYPE_OFFSET =
      PPP_AND_RQI_AND_QFI_OFFSET + PPP_AND_RQI_AND_QFI_SIZE;
  private static final int NEXT_EXTENSION_HEADER_TYPE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;

  private static final int GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH =
      NEXT_EXTENSION_HEADER_TYPE_OFFSET + NEXT_EXTENSION_HEADER_TYPE_SIZE;
  private static final int GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MAX_LENGTH =
      PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_OFFSET + PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_SIZE;

  private byte length;
  private final byte pduType;

  /** UL Common */
  private boolean ppp; // Paging Policy Presence field

  private boolean rqi; // Reflective QoS Indicator field
  private byte qfi; // Qos Flow Identifier field

  /** UL PPI(presence in case ppp is true) */
  private byte ppi; // Paging Policy Indicator field

  private int padding;

  private GtpV1ExtensionHeaderType nextExtensionHeaderType =
      GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new GtpV1PduSessionContainerExtensionHeader object.
   * @throws org.pcap4j.packet.IllegalRawDataException if parsing the raw data fails.
   */
  public static GtpV1PduSessionContainerExtensionHeader newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpV1PduSessionContainerExtensionHeader(rawData, offset, length);
  }

  private GtpV1PduSessionContainerExtensionHeader(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH) {
      StringBuilder sb = new StringBuilder(80);
      sb.append("The data is too short to build an GTP Pdu session container extension header(")
          .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    int lengthInRaw = (ByteArrays.getByte(rawData, LENGTH_OFFSET + offset)) & 0xFF;
    if (lengthInRaw != GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH / 4
        && lengthInRaw != GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MAX_LENGTH / 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The length filed value must be ")
          .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH / 4)
          .append(" or ")
          .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MAX_LENGTH / 4)
          .append(", but it is ")
          .append(lengthInRaw);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = (byte) lengthInRaw;

    byte pduTypeAndSpare = ByteArrays.getByte(rawData, PDU_TYPE_AND_SPARE_OFFSET + offset);
    this.pduType = (byte) ((pduTypeAndSpare & 0xF0) >>> 4);

    if (pduType == 0) {
      byte pppAndRqiAndQfi = ByteArrays.getByte(rawData, PPP_AND_RQI_AND_QFI_OFFSET + offset);
      this.ppp = ((pppAndRqiAndQfi & 0x80) >>> 7) != 0;
      this.rqi = ((pppAndRqiAndQfi & 0x40) >> 6) != 0;
      this.qfi = (byte) (pppAndRqiAndQfi & 0x3F);

      if (ppp) {
        byte ppiAndSpare = ByteArrays.getByte(rawData, PPI_AND_SPARE_OFFSET + offset);
        this.ppi = (byte) ((ppiAndSpare & 0xF0) >>> 4);
        int paddingAndNextExtensionHeaderType =
            ByteArrays.getInt(rawData, PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset);
        this.padding = (paddingAndNextExtensionHeaderType & 0xFFFFFF00) >>> 8;
        this.nextExtensionHeaderType =
            GtpV1ExtensionHeaderType.getInstance(
                (byte) (paddingAndNextExtensionHeaderType & 0x000000FF));
      } else {
        this.nextExtensionHeaderType =
            GtpV1ExtensionHeaderType.getInstance(
                ByteArrays.getByte(rawData, NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset));
      }
    } else if (pduType == 1) {
      byte spareAndQfi = ByteArrays.getByte(rawData, SPARE_AND_QFI_OFFSET + offset);
      this.qfi = (byte) (spareAndQfi & 0x3F);
      this.nextExtensionHeaderType =
          GtpV1ExtensionHeaderType.getInstance(
              ByteArrays.getByte(rawData, NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset));
    }
  }

  private GtpV1PduSessionContainerExtensionHeader(Builder builder) {
    this.pduType = builder.pduType;
    this.ppp = builder.ppp;
    this.rqi = builder.rqi;
    this.qfi = builder.qfi;
    this.ppi = builder.ppi;
    this.padding = builder.padding;
    this.nextExtensionHeaderType = builder.nextExtensionHeaderType;

    if (builder.correctLengthAtBuild) {
      this.length = 1;
      if (pduType == 0 && ppp) {
        this.length = 2;
      }
    } else {
      this.length = builder.length;
    }
  }

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length as int */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return pduType */
  public byte getPduType() {
    return pduType;
  }

  /** @return ppp */
  public boolean isPpp() {
    return ppp;
  }

  /** @return rqi */
  public boolean isRqi() {
    return rqi;
  }

  /** @return qfi */
  public byte getQfi() {
    return qfi;
  }

  /** @return ppi */
  public byte getPpi() {
    return ppi;
  }

  /** @return padding */
  public int getPadding() {
    return padding;
  }

  /** @return nextExtensionHeaderType */
  @Override
  public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
    return nextExtensionHeaderType;
  }

  @Override
  public byte[] getRawData() {
    List<byte[]> rawFields = new ArrayList<>();
    rawFields.add(ByteArrays.toByteArray(length));
    rawFields.add(ByteArrays.toByteArray((byte) (pduType << 4)));
    if (pduType == 0) {
      byte firstByte = 0;
      int lastInt = 0;
      if (ppp) {
        firstByte |= 0x80;
        lastInt = (ppi << 28) | (padding & 0x00FFFFFF);
      }
      if (rqi) {
        firstByte |= 0x40;
      }
      firstByte |= qfi & 0x3F;
      rawFields.add(ByteArrays.toByteArray(firstByte));
      rawFields.add(ByteArrays.toByteArray(lastInt));
    } else if (pduType == 1) {
      byte oneByte = (byte) (qfi & 0x3F);
      rawFields.add(ByteArrays.toByteArray(oneByte));
    }
    rawFields.add(ByteArrays.toByteArray(nextExtensionHeaderType.value() & 0xFF));
    return ByteArrays.concatenate(rawFields);
  }

  @Override
  public int length() {
    return getLengthAsInt() * 4;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");
    sb.append("[GTP Pdu Session Container Extension Header (")
        .append(this.length())
        .append(" bytes)]")
        .append(ls)
        .append("  length: ")
        .append(length)
        .append(ls)
        .append("  pdu type: ")
        .append(pduType)
        .append(ls);
    if (pduType == 0) {
      sb.append("  Paging Policy Presence: ")
          .append(ppp)
          .append(ls)
          .append("  Reflective QoS Indicator: ")
          .append(rqi)
          .append(ls)
          .append("  Qos Flow Identifier: ")
          .append(qfi)
          .append(ls);
      if (ppp) {
        sb.append("  Paging Policy Indicator: ").append(ppi).append(ls);
      }
    } else if (pduType == 1) {
      sb.append("  Qos Flow Identifier: ").append(qfi).append(ls);
    }

    sb.append("  nextExtensionHeaderType: ").append(nextExtensionHeaderType).append(ls);
    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 17;
    result = prime * result + length;
    result = prime * result + pduType;
    result = prime * result + (ppp ? 1231 : 1237);
    result = prime * result + (rqi ? 1231 : 1237);
    result = prime * result + qfi;
    result = prime * result + ppi;
    result = prime * result + nextExtensionHeaderType.hashCode();
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

    GtpV1PduSessionContainerExtensionHeader that = (GtpV1PduSessionContainerExtensionHeader) o;
    return length == that.length
        && pduType == that.pduType
        && ppp == that.ppp
        && rqi == that.rqi
        && qfi == that.qfi
        && ppi == that.ppi
        && nextExtensionHeaderType.equals(that.nextExtensionHeaderType);
  }

  public static final class Builder
      implements LengthBuilder<GtpV1PduSessionContainerExtensionHeader> {

    byte length;
    byte pduType;
    boolean ppp; // Paging Policy Presence field
    boolean rqi; // Reflective QoS Indicator field
    byte qfi; // Qos Flow Identifier field
    byte ppi; // Paging Policy Indicator field
    int padding = 0;
    GtpV1ExtensionHeaderType nextExtensionHeaderType;
    boolean correctLengthAtBuild;

    /** */
    public Builder() {
      // Do nothing, just used to create a Builder without fields setting
    }

    private Builder(GtpV1PduSessionContainerExtensionHeader extensionHeader) {
      this.length = extensionHeader.length;
      this.pduType = extensionHeader.pduType;
      this.ppp = extensionHeader.ppp;
      this.rqi = extensionHeader.rqi;
      this.qfi = extensionHeader.qfi;
      this.ppi = extensionHeader.ppi;
      this.padding = extensionHeader.padding;
      this.nextExtensionHeaderType = extensionHeader.nextExtensionHeaderType;
    }

    /**
     * @param length header length in unit of octets
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     * @param pduType pdu type
     * @return this Builder object for method chaining.
     */
    public Builder pduType(byte pduType) {
      this.pduType = pduType;
      return this;
    }

    /**
     * @param ppp Paging Policy Presence
     * @return this Builder object for method chaining.
     */
    public Builder ppp(boolean ppp) {
      this.ppp = ppp;
      return this;
    }

    /**
     * @param rqi Reflective QoS Indicator
     * @return this Builder object for method chaining.
     */
    public Builder rqi(boolean rqi) {
      this.rqi = rqi;
      return this;
    }

    /**
     * @param qfi Qos Flow Identifier
     * @return this Builder object for method chaining.
     */
    public Builder qfi(byte qfi) {
      this.qfi = qfi;
      return this;
    }

    /**
     * @param ppi Paging Policy Indicator
     * @return this Builder object for method chaining.
     */
    public Builder ppi(byte ppi) {
      this.ppi = ppi;
      return this;
    }

    /**
     * @param padding padding
     * @return this Builder object for method chaining.
     */
    public Builder padding(int padding) {
      this.padding = padding;
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

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    /**
     * Build a GtpV1ExtensionHeader object using values set to this object.
     *
     * @return a new GtpV1ExtensionHeader object
     */
    public GtpV1PduSessionContainerExtensionHeader build() {
      return new GtpV1PduSessionContainerExtensionHeader(this);
    }
  }
}
