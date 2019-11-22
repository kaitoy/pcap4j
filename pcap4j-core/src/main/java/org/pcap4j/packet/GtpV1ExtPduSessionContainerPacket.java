/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.GtpV1ExtPduSessionContainerPduType;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Leo Ma
 * @author Kaito Yamada
 * @since pcap4j 1.8.3
 */
public class GtpV1ExtPduSessionContainerPacket extends AbstractPacket {

  private static final long serialVersionUID = 7361463927403478495L;

  private final GtpV1ExtPduSessionContainerHeader header;
  private final Packet payload;

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
  public static GtpV1ExtPduSessionContainerPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpV1ExtPduSessionContainerPacket(rawData, offset, length);
  }

  private GtpV1ExtPduSessionContainerPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new GtpV1ExtPduSessionContainerHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      Packet nextPacket;
      if (!header.nextExtensionHeaderType.equals(
          GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS)) {
        nextPacket =
            PacketFactories.getFactory(Packet.class, GtpV1ExtensionHeaderType.class)
                .newInstance(
                    rawData,
                    offset + header.length(),
                    payloadLength,
                    header.nextExtensionHeaderType);
      } else {
        nextPacket =
            PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(
                    rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
      }
      this.payload = nextPacket;
    } else {
      this.payload = null;
    }
  }

  private GtpV1ExtPduSessionContainerPacket(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder must not be null.");
    }
    if (builder.pduType == null || builder.nextExtensionHeaderType == null) {
      StringBuilder sb = new StringBuilder();
      sb.append(" builder.pduType: ")
          .append(builder.pduType)
          .append(" builder.nextExtensionHeaderType: ")
          .append(builder.nextExtensionHeaderType);
      throw new NullPointerException(sb.toString());
    }
    if (builder.ppi != null && builder.spare2 == null) {
      throw new NullPointerException("builder.spare2 must not be null if builder.ppi is not null.");
    }

    if ((builder.spare1 & 0xF0) != 0) {
      throw new IllegalArgumentException(
          "(builder.spare1 & 0xF0) must be zero. builder.spare1: " + builder.spare1);
    }
    if ((builder.qfi & 0xC0) != 0) {
      throw new IllegalArgumentException(
          "(builder.qfi & 0xC0) must be zero. builder.qfi: " + builder.qfi);
    }
    if (builder.ppi != null) {
      if ((builder.ppi & 0xF8) != 0) {
        throw new IllegalArgumentException(
            "(builder.ppi & 0xF8) must be zero. builder.ppi: " + builder.ppi);
      }
      if ((builder.spare2 & 0xE0) != 0) {
        throw new IllegalArgumentException(
            "(builder.spare2 & 0xE0) must be zero. builder.spare2: " + builder.spare2);
      }
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new GtpV1ExtPduSessionContainerHeader(builder);
  }

  @Override
  public GtpV1ExtPduSessionContainerHeader getHeader() {
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
   * @author Leo Ma
   * @author Kaito Yamada
   * @since pcap4j 1.8.3
   */
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<GtpV1ExtPduSessionContainerPacket> {

    private byte extensionHeaderLength;
    private GtpV1ExtPduSessionContainerPduType pduType;
    private byte spare1;
    private boolean ppp;
    private boolean rqi;
    private byte qfi;
    private Byte ppi;
    private Byte spare2;
    private byte[] padding;
    private GtpV1ExtensionHeaderType nextExtensionHeaderType;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;
    private boolean paddingAtBuild;

    /** */
    public Builder() {
      // Do nothing, just used to create a Builder without fields setting
    }

    /** @param packet packet */
    public Builder(GtpV1ExtPduSessionContainerPacket packet) {
      this.extensionHeaderLength = packet.header.extensionHeaderLength;
      this.pduType = packet.header.pduType;
      this.spare1 = packet.header.spare1;
      this.ppp = packet.header.ppp;
      this.rqi = packet.header.rqi;
      this.qfi = packet.header.qfi;
      this.ppi = packet.header.ppi;
      this.spare2 = packet.header.spare2;
      this.padding = packet.header.padding;
      this.nextExtensionHeaderType = packet.header.nextExtensionHeaderType;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param extensionHeaderLength Extension Header Length
     * @return this Builder object for method chaining.
     */
    public Builder extensionHeaderLength(byte extensionHeaderLength) {
      this.extensionHeaderLength = extensionHeaderLength;
      return this;
    }

    /**
     * @param pduType PDU type
     * @return this Builder object for method chaining.
     */
    public Builder pduType(GtpV1ExtPduSessionContainerPduType pduType) {
      this.pduType = pduType;
      return this;
    }

    /**
     * @param spare1 first spare field
     * @return this Builder object for method chaining.
     */
    public Builder spare1(byte spare1) {
      this.spare1 = spare1;
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
    public Builder ppi(Byte ppi) {
      this.ppi = ppi;
      return this;
    }

    /**
     * The second spare field. If ppi is set to non-null, spare2 must be set to non-null. If ppi is
     * set to null, the value set to spare2 will be ignored at build.
     *
     * @param spare2 second spare field
     * @return this Builder object for method chaining.
     */
    public Builder spare2(Byte spare2) {
      this.spare2 = spare2;
      return this;
    }

    /**
     * @param padding padding
     * @return this Builder object for method chaining.
     */
    public Builder padding(byte[] padding) {
      this.padding = padding;
      return this;
    }

    /**
     * @param nextExtensionHeaderType Next Extension Header Type
     * @return this Builder object for method chaining.
     */
    public Builder nextExtensionHeaderType(GtpV1ExtensionHeaderType nextExtensionHeaderType) {
      this.nextExtensionHeaderType = nextExtensionHeaderType;
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

    /**
     * @param paddingAtBuild paddingAtBuild
     * @return this Builder object for method chaining.
     */
    public Builder paddingAtBuild(boolean paddingAtBuild) {
      this.paddingAtBuild = paddingAtBuild;
      return this;
    }

    /**
     * Build a GtpV1ExtensionHeader object using values set to this object.
     *
     * @return a new GtpV1ExtensionHeader object
     */
    @Override
    public GtpV1ExtPduSessionContainerPacket build() {
      return new GtpV1ExtPduSessionContainerPacket(this);
    }
  }

  /**
   * PDI Session Container GTP Extension Header which carry PDU session information
   *
   * <pre style="white-space: pre;">
   *    8     7     6     5     4     3     2     1
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |            Extension Header Length            |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |             PDU Session Container             |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |         Next Extension Header Type            |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * </pre>
   *
   * The PDU Session Container has a variable length and its content varies depending on PDU Type
   * and PPP.
   *
   * <pre style="white-space: pre;">
   * PDU Type=0 and PPP is false:
   *
   *    8     7     6     5     4     3     2     1
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |       PDU Type(=0)    |         Spare         |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * | PPP | RQI |        QoS Flow Identifier        |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   *
   * PDU Type=0 and PPP is true:
   *
   *    8     7     6     5     4     3     2     1
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
   *
   * PDU Type=1:
   *
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |       PDU Type(=1)    |         Spare         |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |   Spare   |        QoS Flow Identifier        |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * </pre>
   *
   * @see <a href=
   *     "https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf">ETSI
   *     TS 138 415 V15.2.0</a>
   * @author Leo Ma
   * @author Kaito Yamada
   * @since pcap4j 1.8.3
   */
  public static final class GtpV1ExtPduSessionContainerHeader extends AbstractHeader {

    private static final long serialVersionUID = 7361463927403475935L;

    private static final int EXTENSION_HEADER_LENGTH_OFFSET = 0;
    private static final int EXTENSION_HEADER_LENGTH_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
    private static final int PDU_TYPE_AND_SPARE_OFFSET =
        EXTENSION_HEADER_LENGTH_OFFSET + EXTENSION_HEADER_LENGTH_SIZE;
    private static final int PDU_TYPE_AND_SPARE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
    private static final int PPP_AND_RQI_AND_QFI_OFFSET =
        PDU_TYPE_AND_SPARE_OFFSET + PDU_TYPE_AND_SPARE_SIZE;
    private static final int PPP_AND_RQI_AND_QFI_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
    private static final int PPI_AND_SPARE_OFFSET =
        PPP_AND_RQI_AND_QFI_OFFSET + PPP_AND_RQI_AND_QFI_SIZE;
    private static final int NEXT_EXTENSION_HEADER_TYPE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;

    private static final int GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH =
        PPI_AND_SPARE_OFFSET + NEXT_EXTENSION_HEADER_TYPE_SIZE;

    private final byte extensionHeaderLength;
    private final GtpV1ExtPduSessionContainerPduType pduType;
    private final byte spare1;
    private final boolean ppp;
    private final boolean rqi;
    private final byte qfi;
    private final Byte ppi;
    private final Byte spare2;
    private final byte[] padding;
    private final GtpV1ExtensionHeaderType nextExtensionHeaderType;

    private GtpV1ExtPduSessionContainerHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an GTP PDU Session Container Extension header (")
            .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.extensionHeaderLength =
          ByteArrays.getByte(rawData, EXTENSION_HEADER_LENGTH_OFFSET + offset);

      byte pduTypeAndSpare = ByteArrays.getByte(rawData, PDU_TYPE_AND_SPARE_OFFSET + offset);
      this.pduType =
          GtpV1ExtPduSessionContainerPduType.getInstance((byte) ((pduTypeAndSpare & 0xF0) >> 4));
      this.spare1 = (byte) (pduTypeAndSpare & 0x0F);

      byte pppAndRqiAndQfi = ByteArrays.getByte(rawData, PPP_AND_RQI_AND_QFI_OFFSET + offset);

      this.ppp = (pppAndRqiAndQfi & 0x80) != 0;
      this.rqi = (pppAndRqiAndQfi & 0x40) != 0;
      this.qfi = (byte) (pppAndRqiAndQfi & 0x3F);

      if (ppp && length < GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH + 1) {
        StringBuilder sb = new StringBuilder(100);
        sb.append(
                "The data is too short to build an GTP PDU Session Container Extension header with PPI (")
            .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH + 1)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int headerLength = (0xFF & extensionHeaderLength) * 4;
      if (length < headerLength) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an GTP PDU Session Container Extension header (")
            .append(headerLength)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int currentOffsetInHeader = PPI_AND_SPARE_OFFSET;
      if (ppp) {
        byte ppiAndSpare = ByteArrays.getByte(rawData, PPI_AND_SPARE_OFFSET + offset);
        this.ppi = (byte) ((ppiAndSpare & 0xE0) >> 5);
        this.spare2 = (byte) (ppiAndSpare & 0x1F);
        currentOffsetInHeader++;
      } else {
        this.ppi = null;
        this.spare2 = null;
      }

      int paddingLength = headerLength - currentOffsetInHeader - 1;
      if (paddingLength != 0) {
        this.padding =
            ByteArrays.getSubArray(rawData, currentOffsetInHeader + offset, paddingLength);
        currentOffsetInHeader += padding.length;
      } else {
        this.padding = new byte[0];
      }

      this.nextExtensionHeaderType =
          GtpV1ExtensionHeaderType.getInstance(
              ByteArrays.getByte(rawData, currentOffsetInHeader + offset));
    }

    private GtpV1ExtPduSessionContainerHeader(Builder builder) {
      this.pduType = builder.pduType;
      this.spare1 = builder.spare1;
      this.ppp = builder.ppp;
      this.rqi = builder.rqi;
      this.qfi = builder.qfi;
      this.ppi = builder.ppi;
      this.spare2 = builder.spare2;
      this.nextExtensionHeaderType = builder.nextExtensionHeaderType;

      if (builder.paddingAtBuild) {
        int mod = measureLengthWithoutPadding() % 4;
        if (mod != 0) {
          this.padding = new byte[4 - mod];
        } else {
          this.padding = new byte[0];
        }
      } else {
        if (builder.padding != null) {
          this.padding = new byte[builder.padding.length];
          System.arraycopy(builder.padding, 0, padding, 0, padding.length);
        } else {
          this.padding = new byte[0];
        }
      }

      if (builder.correctLengthAtBuild) {
        this.extensionHeaderLength = (byte) (length() / 4);
      } else {
        this.extensionHeaderLength = builder.extensionHeaderLength;
      }
    }

    /** @return extensionHeaderLength */
    public byte getExtensionHeaderLength() {
      return extensionHeaderLength;
    }

    /** @return extensionHeaderLength as int */
    public int getExtensionHeaderLengthAsInt() {
      return 0xFF & extensionHeaderLength;
    }

    /** @return pduType */
    public GtpV1ExtPduSessionContainerPduType getPduType() {
      return pduType;
    }

    /** @return spare 1 (the spare field between PDU type and PPP) */
    public byte getSpare1() {
      return spare1;
    }

    /**
     * Paging Policy Presence field.
     *
     * @return true if the value of PPP field (the 9th bit of PDU Session Container) is 0; false
     *     otherwise.
     */
    public boolean getPpp() {
      return ppp;
    }

    /**
     * Reflective QoS Indicator field.
     *
     * @return true if the value of RQI field (the 10th bit of PDU Session Container) is 0; false
     *     otherwise.
     */
    public boolean getRqi() {
      return rqi;
    }

    /**
     * Qos Flow Identifier field.
     *
     * @return qfi
     */
    public byte getQfi() {
      return qfi;
    }

    /**
     * Paging Policy Indicator field.
     *
     * @return ppi. Maybe null.
     */
    public Byte getPpi() {
      return ppi;
    }

    /**
     * @return spare 2 (the spare field between PPI and padding) if ppi is not null; null otherwise.
     */
    public Byte getSpare2() {
      return spare2;
    }

    /** @return padding */
    public byte[] getPadding() {
      return Arrays.copyOf(padding, padding.length);
    }

    /** @return nextExtensionHeaderType */
    public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
      return nextExtensionHeaderType;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(extensionHeaderLength));
      rawFields.add(ByteArrays.toByteArray((byte) ((pduType.value() << 4) | spare1)));

      byte pppRqiQfi = qfi;
      if (ppp) {
        pppRqiQfi |= 0x80;
      }
      if (rqi) {
        pppRqiQfi |= 0x40;
      }
      rawFields.add(ByteArrays.toByteArray(pppRqiQfi));

      if (ppp) {
        rawFields.add(ByteArrays.toByteArray((byte) ((ppi << 5) | spare2)));
      }

      rawFields.add(padding);
      rawFields.add(ByteArrays.toByteArray(nextExtensionHeaderType.value()));
      return rawFields;
    }

    private int measureLengthWithoutPadding() {
      return ppi == null ? 4 : 5;
    }

    @Override
    protected int calcLength() {
      return measureLengthWithoutPadding() + padding.length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");
      sb.append("[GTP Extension PDU Session Container Header (")
          .append(this.length())
          .append(" bytes)]")
          .append(ls)
          .append("  Extension Header Length: ")
          .append(extensionHeaderLength)
          .append(" (")
          .append(extensionHeaderLength * 4)
          .append(" bytes)")
          .append(ls)
          .append("  PDU Type: ")
          .append(pduType)
          .append(ls)
          .append("  spare 1: 0x")
          .append(ByteArrays.toHexString(spare1, ""))
          .append(ls);
      if (pduType.value() == 0) {
        sb.append("  Paging Policy Presence: ")
            .append(ppp)
            .append(
                ppp
                    ? " (Paging Policy Indicator present)"
                    : " (Paging Policy Indicator not present)")
            .append(ls)
            .append("  Reflective QoS Indicator: ")
            .append(rqi)
            .append(
                rqi
                    ? " (Reflective QoS activation triggered)"
                    : " (Reflective QoS activation not triggered)")
            .append(ls);
      } else {
        sb.append("  Spare bit 1: ")
            .append(ppp ? 1 : 0)
            .append(ls)
            .append("  Spare bit 2: ")
            .append(rqi ? 1 : 0)
            .append(ls);
      }
      sb.append("  Qos Flow Identifier: ").append(qfi).append(ls);
      if (ppi != null) {
        sb.append("  Paging Policy Indicator: ")
            .append(ppi)
            .append(ls)
            .append("  spare 2: 0x")
            .append(ByteArrays.toHexString(spare2, ""))
            .append(ls);
      }
      if (padding.length != 0) {
        sb.append("  Padding: ").append(ByteArrays.toHexString(padding, " ")).append(ls);
      }
      sb.append("  Next Extension Header Type: ").append(nextExtensionHeaderType).append(ls);

      return sb.toString();
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

      GtpV1ExtPduSessionContainerHeader that = (GtpV1ExtPduSessionContainerHeader) o;

      if (extensionHeaderLength != that.extensionHeaderLength) {
        return false;
      }
      if (spare1 != that.spare1) {
        return false;
      }
      if (ppp != that.ppp) {
        return false;
      }
      if (rqi != that.rqi) {
        return false;
      }
      if (qfi != that.qfi) {
        return false;
      }
      if (!pduType.equals(that.pduType)) {
        return false;
      }
      if (ppi != null ? !ppi.equals(that.ppi) : that.ppi != null) {
        return false;
      }
      if (spare2 != null ? !spare2.equals(that.spare2) : that.spare2 != null) {
        return false;
      }
      if (!Arrays.equals(padding, that.padding)) {
        return false;
      }
      return nextExtensionHeaderType.equals(that.nextExtensionHeaderType);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + (int) extensionHeaderLength;
      result = 31 * result + pduType.hashCode();
      result = 31 * result + (int) spare1;
      result = 31 * result + (ppp ? 1 : 0);
      result = 31 * result + (rqi ? 1 : 0);
      result = 31 * result + (int) qfi;
      result = 31 * result + (ppi != null ? ppi.hashCode() : 0);
      result = 31 * result + (spare2 != null ? spare2.hashCode() : 0);
      result = 31 * result + Arrays.hashCode(padding);
      result = 31 * result + nextExtensionHeaderType.hashCode();
      return result;
    }
  }
}
