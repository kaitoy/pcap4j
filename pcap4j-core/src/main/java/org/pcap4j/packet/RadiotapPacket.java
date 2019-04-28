/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Radiotap packet
 *
 * @see <a href="http://www.radiotap.org/">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 4121827899399388949L;

  private static final Logger logger = LoggerFactory.getLogger(RadiotapPacket.class);

  private final RadiotapHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new RadiotapPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapPacket(rawData, offset, length);
  }

  private RadiotapPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new RadiotapHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, DataLinkType.class)
              .newInstance(
                  rawData, offset + header.length(), payloadLength, DataLinkType.IEEE802_11);
    } else {
      this.payload = null;
    }
  }

  private RadiotapPacket(Builder builder) {
    if (builder == null || builder.presentBitmasks == null || builder.dataFields == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.presentBitmasks: ")
          .append(builder.presentBitmasks)
          .append(" builder.dataFields: ")
          .append(builder.dataFields);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new RadiotapHeader(builder);
  }

  @Override
  public RadiotapHeader getHeader() {
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
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<RadiotapPacket> {

    private byte version;
    private byte pad;
    private short length;
    private List<RadiotapPresentBitmask> presentBitmasks;
    private List<RadiotapData> dataFields;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(RadiotapPacket packet) {
      this.version = packet.header.version;
      this.pad = packet.header.pad;
      this.length = packet.header.length;
      this.presentBitmasks = packet.header.presentBitmasks;
      this.dataFields = packet.header.dataFields;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param version version
     * @return this Builder object for method chaining.
     */
    public Builder version(byte version) {
      this.version = version;
      return this;
    }

    /**
     * @param pad pad
     * @return this Builder object for method chaining.
     */
    public Builder pad(byte pad) {
      this.pad = pad;
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
     * @param presentBitmasks presentBitmasks
     * @return this Builder object for method chaining.
     */
    public Builder presentBitmasks(List<RadiotapPresentBitmask> presentBitmasks) {
      this.presentBitmasks = presentBitmasks;
      return this;
    }

    /**
     * @param dataFields dataFields
     * @return this Builder object for method chaining.
     */
    public Builder dataFields(List<RadiotapData> dataFields) {
      this.dataFields = dataFields;
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
    public RadiotapPacket build() {
      return new RadiotapPacket(this);
    }
  }

  /**
   * Radiotap Header + Extended presence masks + Radiotap fields
   *
   * <pre>
   * struct ieee80211_radiotap_header {
   *         u_int8_t        it_version; // currently, this is always 0
   *         u_int8_t        it_pad;     // currently unused, just for for the alignment
   *         u_int16_t       it_len;     // entire length
   *         u_int32_t       it_present; // presence mask
   * } __attribute__((__packed__));
   * </pre>
   *
   * @see <a href="http://www.radiotap.org/">Radiotap</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class RadiotapHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = -5384412750993783312L;

    private static final int VERSION_OFFSET = 0;
    private static final int VERSION_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int PAD_OFFSET = VERSION_OFFSET + VERSION_SIZE;
    private static final int PAD_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int LENGTH_OFFSET = PAD_OFFSET + PAD_SIZE;
    private static final int LENGTH_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int PRESENT_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
    private static final int PRESENT_SIZE = INT_SIZE_IN_BYTES;
    private static final int MIN_RADIOTAP_HEADER_SIZE = PRESENT_OFFSET + PRESENT_SIZE;

    private final byte version;
    private final byte pad;
    private final short length;
    private final List<RadiotapPresentBitmask> presentBitmasks;
    private final List<RadiotapData> dataFields;

    private RadiotapHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < MIN_RADIOTAP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a RadiotapHeader (")
            .append(MIN_RADIOTAP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.version = ByteArrays.getByte(rawData, VERSION_OFFSET + offset);
      this.pad = ByteArrays.getByte(rawData, PAD_OFFSET + offset);
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset, ByteOrder.LITTLE_ENDIAN);
      this.presentBitmasks = new ArrayList<RadiotapPresentBitmask>();

      if (length < getLengthAsInt()) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a RadiotapHeader (")
            .append(getLengthAsInt())
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (getLengthAsInt() < MIN_RADIOTAP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The value of the length field is too small to build a RadiotapHeader (")
            .append(MIN_RADIOTAP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      String namespace = "";
      int bitNumOffset = 0;
      int remainingLength = getLengthAsInt() - PRESENT_OFFSET;
      int nextPresentOffset = offset + PRESENT_OFFSET;
      while (true) {
        if (remainingLength < INT_SIZE_IN_BYTES) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("Something went wrong during parsing present bitmasks. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length);
          throw new IllegalRawDataException(sb.toString());
        }

        RadiotapPresentBitmask mask =
            RadiotapPresentBitmask.newInstance(
                rawData, nextPresentOffset, remainingLength, bitNumOffset, namespace);
        presentBitmasks.add(mask);

        nextPresentOffset += INT_SIZE_IN_BYTES;
        remainingLength -= INT_SIZE_IN_BYTES;
        if (!mask.isAnotherBitmapFollows()) {
          break;
        }
        if (mask.isRadiotapNamespaceNext()) {
          namespace = "";
          bitNumOffset = 0;
        } else if (mask.isVendorNamespaceNext()) {
          namespace = "unknown";
          bitNumOffset = 0;
        } else {
          bitNumOffset += 32;
        }
      }

      this.dataFields = new ArrayList<RadiotapData>();
      int nextFieldOffset = nextPresentOffset;
      PacketFactory<RadiotapData, RadiotapPresentBitNumber> factory =
          PacketFactories.getFactory(RadiotapData.class, RadiotapPresentBitNumber.class);
      Class<? extends RadiotapData> unknownDataFieldClass = factory.getTargetClass();
      boolean breaking = false;
      try {
        for (RadiotapPresentBitmask mask : presentBitmasks) {
          if (breaking) {
            break;
          }

          for (RadiotapPresentBitNumber num : mask.getBitNumbers()) {
            int alignment = num.getRequiredAlignment();
            int padSize = alignment - ((nextFieldOffset - offset) % alignment);
            if (padSize != alignment) {
              if (remainingLength < padSize) {
                StringBuilder sb = new StringBuilder(200);
                sb.append("Not enough length for a RadiotapDataPad: ")
                    .append(ByteArrays.toHexString(rawData, " "))
                    .append(", offset: ")
                    .append(offset)
                    .append(", length: ")
                    .append(length);
                throw new IllegalRawDataException(sb.toString());
              }

              RadiotapData pad = RadiotapDataPad.newInstance(rawData, nextFieldOffset, padSize);
              dataFields.add(pad);
              nextFieldOffset += padSize;
              remainingLength -= padSize;
            }

            if (remainingLength <= 0) {
              StringBuilder sb = new StringBuilder(200);
              sb.append("No data is remaining for a RadiotapDataField: ")
                  .append(ByteArrays.toHexString(rawData, " "))
                  .append(", offset: ")
                  .append(offset)
                  .append(", length: ")
                  .append(length);
              throw new IllegalRawDataException(sb.toString());
            }

            RadiotapData field =
                factory.newInstance(rawData, nextFieldOffset, remainingLength, num);
            dataFields.add(field);
            int fieldLen = field.length();
            nextFieldOffset += fieldLen;
            remainingLength -= fieldLen;

            if (field.getClass().equals(unknownDataFieldClass)) {
              breaking = true;
              break;
            }
          }
        }
      } catch (Exception e) {
        logger.error("Exception occurred during analyzing Radiotap data fields: ", e);
      }

      if (remainingLength != 0) {
        dataFields.add(factory.newInstance(rawData, nextFieldOffset, remainingLength));
      }
    }

    private RadiotapHeader(Builder builder) {
      this.version = builder.version;
      this.pad = builder.pad;
      this.presentBitmasks = new ArrayList<RadiotapPresentBitmask>(builder.presentBitmasks);
      this.dataFields = new ArrayList<RadiotapData>(builder.dataFields);

      if (builder.correctLengthAtBuild) {
        this.length = (short) calcLength();
      } else {
        this.length = builder.length;
      }
    }

    /** @return version */
    public byte getVersion() {
      return version;
    }

    /** @return version */
    public int getVersionAsInt() {
      return version & 0xFF;
    }

    /** @return pad */
    public byte getPad() {
      return pad;
    }

    /** @return length */
    public short getLength() {
      return length;
    }

    /** @return length */
    public int getLengthAsInt() {
      return 0xFFFF & length;
    }

    /** @return presentBitmasks */
    public ArrayList<RadiotapPresentBitmask> getPresentBitmasks() {
      return new ArrayList<RadiotapPresentBitmask>(presentBitmasks);
    }

    /** @return dataFields */
    public ArrayList<RadiotapData> getDataFields() {
      return new ArrayList<RadiotapData>(dataFields);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(version));
      rawFields.add(ByteArrays.toByteArray(pad));
      rawFields.add(ByteArrays.toByteArray(length, ByteOrder.LITTLE_ENDIAN));
      for (RadiotapPresentBitmask mask : presentBitmasks) {
        rawFields.add(mask.getRawData());
      }
      for (RadiotapData field : dataFields) {
        rawFields.add(field.getRawData());
      }
      return rawFields;
    }

    @Override
    public int calcLength() {
      int len = 1 + 1 + 2;
      len += presentBitmasks.size() * INT_SIZE_IN_BYTES;
      for (RadiotapData field : dataFields) {
        len += field.length();
      }
      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Radiotap header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Version: ").append(getVersionAsInt()).append(ls);
      sb.append("  Pad: ").append(pad).append(ls);
      sb.append("  Length: ").append(getLengthAsInt()).append(ls);
      for (RadiotapPresentBitmask mask : presentBitmasks) {
        sb.append(mask.toString("  "));
      }
      sb.append("  Data Fields: ").append(ls);
      for (RadiotapData field : dataFields) {
        sb.append(field.toString("    "));
      }

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

      RadiotapHeader other = (RadiotapHeader) obj;
      return length == other.length
          && version == other.version
          && pad == other.pad
          && presentBitmasks.equals(other.presentBitmasks)
          && dataFields.equals(other.dataFields);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + version;
      result = 31 * result + pad;
      result = 31 * result + length;
      result = 31 * result + presentBitmasks.hashCode();
      result = 31 * result + dataFields.hashCode();
      return result;
    }
  }

  /**
   * The interface representing a Radiotap data field. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static RadiotapDataField newInstance(byte[] rawData, int
   * offset, int length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public interface RadiotapData extends Serializable {

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();

    /**
     * @param indent indent
     * @return String representation of this object.
     */
    public String toString(String indent);
  }
}
