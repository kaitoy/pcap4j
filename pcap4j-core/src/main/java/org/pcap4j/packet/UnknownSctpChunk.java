/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.namednumber.SctpChunkType;
import org.pcap4j.util.ByteArrays;

/**
 * Unknown SCTP Chunk
 *
 * <pre style="white-space: pre;">
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * \                                                               \
 * /                          Chunk Value                          /
 * \                                                               \
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class UnknownSctpChunk implements SctpChunk {

  /** */
  private static final long serialVersionUID = 2870805088630768174L;

  private final SctpChunkType type;
  private final byte flags;
  private final short length;
  private final byte[] value;
  private final byte[] padding;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownSctpChunk object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownSctpChunk newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownSctpChunk(rawData, offset, length);
  }

  private UnknownSctpChunk(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.type = SctpChunkType.getInstance(rawData[offset]);
    this.flags = rawData[1 + offset];
    this.length = ByteArrays.getShort(rawData, 2 + offset);
    int lengthAsInt = getLengthAsInt();
    if (length < lengthAsInt) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option (")
          .append(lengthAsInt)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (lengthAsInt < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The value of the length field must be more than 3. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    if (lengthAsInt > 4) {
      this.value = ByteArrays.getSubArray(rawData, 4 + offset, lengthAsInt - 4);

      int paddingLen = 4 - lengthAsInt % 4;
      if (paddingLen != 0 && paddingLen != 4 && length >= lengthAsInt + paddingLen) {
        this.padding = new byte[paddingLen];
        System.arraycopy(rawData, lengthAsInt + offset, padding, 0, paddingLen);
      } else {
        this.padding = new byte[0];
      }
    } else {
      this.value = new byte[0];
      this.padding = new byte[0];
    }
  }

  private UnknownSctpChunk(Builder builder) {
    if (builder == null || builder.type == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.type: ").append(builder.type);
      throw new NullPointerException(sb.toString());
    }
    if (builder.value.length + 4 > 0xFFFF) {
      StringBuilder sb =
          new StringBuilder()
              .append("(value.length + 4) must be less than or equal to 0xFFFF. builder.value: ")
              .append(ByteArrays.toHexString(builder.value, " "));
      throw new IllegalArgumentException(sb.toString());
    }

    this.type = builder.type;
    this.flags = builder.flags;
    if (builder.value != null) {
      this.value = ByteArrays.clone(builder.value);
    } else {
      this.value = new byte[0];
    }

    if (builder.correctLengthAtBuild) {
      this.length = (short) (4 + value.length);
    } else {
      this.length = builder.length;
    }

    if (builder.paddingAtBuild) {
      int paddingLen = 4 - (value.length + 4) % 4;
      if (paddingLen != 0 && paddingLen != 4) {
        this.padding = new byte[paddingLen];
      } else {
        this.padding = new byte[0];
      }
    } else {
      if (builder.padding != null) {
        this.padding = ByteArrays.clone(builder.padding);
      } else {
        this.padding = new byte[0];
      }
    }
  }

  @Override
  public SctpChunkType getType() {
    return type;
  }

  /** @return flags */
  public byte getFlags() {
    return flags;
  }

  /** @return length */
  public short getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFFFF & length;
  }

  /** @return value */
  public byte[] getValue() {
    return ByteArrays.clone(value);
  }

  /** @return padding */
  public byte[] getPadding() {
    return ByteArrays.clone(padding);
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = type.value();
    rawData[1] = flags;
    rawData[2] = (byte) (length >> 8);
    rawData[3] = (byte) length;
    if (value.length != 0) {
      System.arraycopy(value, 0, rawData, 4, value.length);
    }
    if (padding.length != 0) {
      System.arraycopy(padding, 0, rawData, 4 + value.length, padding.length);
    }
    return rawData;
  }

  @Override
  public int length() {
    return 4 + value.length + padding.length;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Type: ")
        .append(type)
        .append(", Flags: 0x")
        .append(ByteArrays.toHexString(flags, " "))
        .append(", Length: ")
        .append(getLengthAsInt())
        .append(" bytes");
    if (value.length != 0) {
      sb.append(", Value: 0x").append(ByteArrays.toHexString(value, ""));
    }
    if (padding.length != 0) {
      sb.append(", Padding: 0x").append(ByteArrays.toHexString(padding, ""));
    }
    sb.append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + flags;
    result = prime * result + length;
    result = prime * result + Arrays.hashCode(padding);
    result = prime * result + type.hashCode();
    result = prime * result + Arrays.hashCode(value);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    UnknownSctpChunk other = (UnknownSctpChunk) obj;
    if (flags != other.flags) return false;
    if (length != other.length) return false;
    if (!Arrays.equals(padding, other.padding)) return false;
    if (!type.equals(other.type)) return false;
    if (!Arrays.equals(value, other.value)) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static final class Builder implements LengthBuilder<UnknownSctpChunk> {

    private SctpChunkType type;
    private byte flags;
    private short length;
    private byte[] value;
    private byte[] padding;
    private boolean correctLengthAtBuild;
    private boolean paddingAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownSctpChunk obj) {
      this.type = obj.type;
      this.flags = obj.flags;
      this.length = obj.length;
      this.value = obj.value;
      this.padding = obj.padding;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(SctpChunkType type) {
      this.type = type;
      return this;
    }

    /**
     * @param flags flags
     * @return this Builder object for method chaining.
     */
    public Builder flags(byte flags) {
      this.flags = flags;
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
     * @param value value
     * @return this Builder object for method chaining.
     */
    public Builder value(byte[] value) {
      this.value = value;
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
     * @param paddingAtBuild paddingAtBuild
     * @return this Builder object for method chaining.
     */
    public Builder paddingAtBuild(boolean paddingAtBuild) {
      this.paddingAtBuild = paddingAtBuild;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public UnknownSctpChunk build() {
      return new UnknownSctpChunk(this);
    }
  }
}
