/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Leo Ma
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
  public static GtpV1ExtPduSessionContainerPacket newPacket(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new GtpV1ExtPduSessionContainerPacket(rawData, offset, length);
  }
  
  private GtpV1ExtPduSessionContainerPacket(byte[] rawData, int offset, int length)
          throws IllegalRawDataException {
    this.header = new GtpV1ExtPduSessionContainerHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      Packet nextPacket;
      if (!header.nextExtHeaderType.equals(GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS)) {
        nextPacket = PacketFactories.getFactory(Packet.class, GtpV1ExtensionHeaderType.class)
                .newInstance(rawData, offset + header.length(), payloadLength, header.nextExtHeaderType);
      } else {
        nextPacket =
                PacketFactories.getFactory(Packet.class, NotApplicable.class)
                    .newInstance(rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
      }
      this.payload = nextPacket;
    } else {
      this.payload = null;
    }
  }
  
  private GtpV1ExtPduSessionContainerPacket(Builder builder) {
    if (builder == null || builder.nextExtHeaderType == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextExtHeaderType: ")
          .append(builder.nextExtHeaderType);
      throw new NullPointerException(sb.toString());
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


  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<GtpV1ExtPduSessionContainerPacket> {

    private byte extHeaderLength;
    private byte pduType;
    private byte spare1;
    private byte spare2;
    private boolean ppp; // Paging Policy Presence field
    private boolean rqi; // Reflective QoS Indicator field
    private byte qfi; // Qos Flow Identifier field
    private Byte ppi; // Paging Policy Indicator field
    private byte[] padding = new byte[] {0x00, 0x00, 0x00};
    private GtpV1ExtensionHeaderType nextExtHeaderType;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {
      // Do nothing, just used to create a Builder without fields setting
    }

    public Builder(GtpV1ExtPduSessionContainerPacket packet) {
      this.extHeaderLength = packet.header.extHeaderlength;
      this.pduType = packet.header.pduType;
      this.spare1 = packet.header.spare1;
      this.spare2 = packet.header.spare2;
      this.ppp = packet.header.ppp;
      this.rqi = packet.header.rqi;
      this.qfi = packet.header.qfi;
      this.ppi = packet.header.ppi;
      this.padding = packet.header.padding;
      this.nextExtHeaderType = packet.header.nextExtHeaderType;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param extHeaderLength header length in unit of octets
     * @return this Builder object for method chaining.
     */
    public Builder extensionHeaderLength(byte extHeaderLength) {
      this.extHeaderLength = extHeaderLength;
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
     * @param spare1 first spare field
     * @return this Builder object for method chaining.
     */
    public Builder spare1(byte spare1) {
      this.spare1 = spare1;
      return this;
    }

    /**
     * @param spare2 second spare field
     * @return this Builder object for method chaining.
     */
    public Builder spare2(byte spare2) {
      this.spare2 = spare2;
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
    public Builder padding(byte[] padding) {
      this.padding = padding;
      return this;
    }

    /**
     * @param nextExtensionHeaderType nextExtensionHeaderType
     * @return this Builder object for method chaining.
     */
    public Builder nextExtensionHeaderType(GtpV1ExtensionHeaderType nextExtensionHeaderType) {
      this.nextExtHeaderType = nextExtensionHeaderType;
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
   * @author Leo Ma
   * @since pcap4j 1.8.3
   */
  public static final class GtpV1ExtPduSessionContainerHeader extends AbstractHeader {
     /**
      *  PDI Session Container GTP Extension Header which carry PDU session information
      *
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
      */
      
      private static final long serialVersionUID = 7361463927403475935L;
      
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

      private byte extHeaderlength;
      private final byte pduType;
      private final byte spare1;
      private byte spare2;

      /** UL Common */
      private boolean ppp; // Paging Policy Presence field

      private boolean rqi; // Reflective QoS Indicator field
      private byte qfi; // Qos Flow Identifier field

      /** UL PPI(presence in case ppp is true) */
      private Byte ppi; // Paging Policy Indicator field

      private byte[] padding;

      private GtpV1ExtensionHeaderType nextExtHeaderType =
          GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS;

      private GtpV1ExtPduSessionContainerHeader(byte[] rawData, int offset, int length)
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

        int extHeaderLengthInRaw = (ByteArrays.getByte(rawData, LENGTH_OFFSET + offset)) & 0xFF;
        if (extHeaderLengthInRaw != GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH / 4
            && extHeaderLengthInRaw != GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MAX_LENGTH / 4) {
          StringBuilder sb = new StringBuilder(100);
          sb.append("The length filed value must be ")
              .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH / 4)
              .append(" or ")
              .append(GTPV1_PDU_SESSION_CONTAINER_EXTENSION_MAX_LENGTH / 4)
              .append(", but it is ")
              .append(extHeaderLengthInRaw);
          throw new IllegalRawDataException(sb.toString());
        }

        this.extHeaderlength = (byte) extHeaderLengthInRaw;

        byte pduTypeAndSpare = ByteArrays.getByte(rawData, PDU_TYPE_AND_SPARE_OFFSET + offset);
        this.pduType = (byte) ((pduTypeAndSpare & 0xF0) >>> 4);
        this.spare1 = (byte) (pduTypeAndSpare & 0x0F);

        if (pduType == 0) {
          byte pppAndRqiAndQfi = ByteArrays.getByte(rawData, PPP_AND_RQI_AND_QFI_OFFSET + offset);
          this.ppp = ((pppAndRqiAndQfi & 0x80) >>> 7) != 0;
          this.rqi = ((pppAndRqiAndQfi & 0x40) >> 6) != 0;
          this.qfi = (byte) (pppAndRqiAndQfi & 0x3F);

          if (ppp) {
            byte ppiAndSpare = ByteArrays.getByte(rawData, PPI_AND_SPARE_OFFSET + offset);
            this.ppi = (byte) ((ppiAndSpare & 0xF0) >>> 5);
            this.spare2 = (byte) (ppiAndSpare & 0x1F);
            int paddingAndNextExtHeaderType =
                ByteArrays.getInt(rawData, PADDING_AND_NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset);
            this.padding = new byte[] {(byte) ((paddingAndNextExtHeaderType >> 24) & 0xFF),
                                       (byte) ((paddingAndNextExtHeaderType >> 16) & 0xFF),
                                       (byte) ((paddingAndNextExtHeaderType >> 8) & 0xFF)};
            this.nextExtHeaderType =
                GtpV1ExtensionHeaderType.getInstance(
                    (byte) (paddingAndNextExtHeaderType & 0x000000FF));
          } else {
            this.nextExtHeaderType =
                GtpV1ExtensionHeaderType.getInstance(
                    ByteArrays.getByte(rawData, NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset));
          }
        } else if (pduType == 1) {
          byte spareAndQfi = ByteArrays.getByte(rawData, SPARE_AND_QFI_OFFSET + offset);
          this.spare2 = (byte) ((spareAndQfi & 0xC0) >>> 6);
          this.qfi = (byte) (spareAndQfi & 0x3F);
          this.nextExtHeaderType =
              GtpV1ExtensionHeaderType.getInstance(
                  ByteArrays.getByte(rawData, NEXT_EXTENSION_HEADER_TYPE_OFFSET + offset));
        }
      }

      private GtpV1ExtPduSessionContainerHeader(Builder builder) {
        this.pduType = builder.pduType;
        this.spare1 = builder.spare1;
        this.spare2 = builder.spare2;
        this.ppp = builder.ppp;
        this.rqi = builder.rqi;
        this.qfi = builder.qfi;
        this.ppi = builder.ppi;
        this.padding = builder.padding;
        this.nextExtHeaderType = builder.nextExtHeaderType;

        if (builder.correctLengthAtBuild) {
          this.extHeaderlength = 1;
          if (pduType == 0 && ppp) {
            this.extHeaderlength = 2;
          }
        } else {
          this.extHeaderlength = builder.extHeaderLength;
        }
      }

      /** @return length */
      public byte getExtensionHeaderLength() {
        return extHeaderlength;
      }

      /** @return length as int */
      public int getLengthAsInt() {
        return 0xFF & extHeaderlength;
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
      public Byte getPpi() {
        return ppi;
      }

      /** @return padding */
      public byte[] getPadding() {
        return padding;
      }

      /** @return nextExtensionHeaderType */
      public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
        return nextExtHeaderType;
      }

      @Override
      protected List<byte[]> getRawFields() {
        List<byte[]> rawFields = new ArrayList<>();
        rawFields.add(ByteArrays.toByteArray(extHeaderlength));
        rawFields.add(ByteArrays.toByteArray((byte) ((pduType << 4) | (spare1 & 0x0F))));
        if (pduType == 0) {
          byte firstByte = 0;
          if (ppp) {
            firstByte |= 0x80;
          }
          if (rqi) {
            firstByte |= 0x40;
          }
          firstByte |= qfi & 0x3F;
          rawFields.add(ByteArrays.toByteArray(firstByte));
          if (ppp) {
              rawFields.add(ByteArrays.toByteArray((byte) ((ppi.byteValue() << 5) | (spare2 & 0x1F))));
              rawFields.add(padding);
          }
        } else if (pduType == 1) {
          byte oneByte = (byte) ((spare2 << 6) | (qfi & 0x3F));
          rawFields.add(ByteArrays.toByteArray(oneByte));
        }
        rawFields.add(ByteArrays.toByteArray((byte) (nextExtHeaderType.value().byteValue() & 0xFF)));
        return rawFields;
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
            .append(extHeaderlength)
            .append(ls)
            .append("  pdu type: ")
            .append(pduType)
            .append(ls)
            .append("  first spare: ")
            .append(spare1)
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
            sb.append("  Paging Policy Indicator: ")
            	.append(ppi)
            	.append(ls)
              .append("  second spare: ")
            	.append(spare2)
            	.append(ls);
          }
        } else if (pduType == 1) {
          sb.append("  second spare: ")
          	.append(spare2)
          	.append(ls)
            .append("  Qos Flow Identifier: ")
          	.append(qfi)
          	.append(ls);
        }

        sb.append("  nextExtensionHeaderType: ").append(nextExtHeaderType).append(ls);
        return sb.toString();
      }

      @Override
      public int hashCode() {
        final int prime = 31;
        int result = 17;
        result = prime * result + extHeaderlength;
        result = prime * result + pduType;
        result = prime * result + spare1;
        result = prime * result + spare2;
        result = prime * result + (ppp ? 1231 : 1237);
        result = prime * result + (rqi ? 1231 : 1237);
        result = prime * result + qfi;
        result = prime * result + ppi.byteValue();
        result = prime * result + nextExtHeaderType.hashCode();
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

        GtpV1ExtPduSessionContainerHeader that = (GtpV1ExtPduSessionContainerHeader) o;
        return extHeaderlength == that.extHeaderlength
            && pduType == that.pduType
            && spare1 == that.spare1
            && spare2 == that.spare2
            && ppp == that.ppp
            && rqi == that.rqi
            && qfi == that.qfi
            && ppi.equals(that.ppi)
            && nextExtHeaderType.equals(that.nextExtHeaderType);
      }
  }
}
