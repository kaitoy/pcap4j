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
 * Illegal SCTP Chunk
 *
 * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class IllegalSctpChunk implements SctpChunk {

  /** */
  private static final long serialVersionUID = 7163848436153227901L;

  private final SctpChunkType type;
  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownSctpChunk object.
   */
  public static IllegalSctpChunk newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalSctpChunk(rawData, offset, length);
  }

  private IllegalSctpChunk(byte[] rawData, int offset, int length) {
    this.type = SctpChunkType.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalSctpChunk(Builder builder) {
    if (builder == null || builder.type == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.type: ")
          .append(builder.type)
          .append(" builder.rawData: ")
          .append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    this.type = builder.type;
    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(builder.rawData, 0, this.rawData, 0, builder.rawData.length);
  }

  @Override
  public SctpChunkType getType() {
    return type;
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("[Type: ").append(type);
    sb.append(", Illegal Raw Data: 0x").append(ByteArrays.toHexString(rawData, ""));
    sb.append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(rawData);
    result = prime * result + type.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    IllegalSctpChunk other = (IllegalSctpChunk) obj;
    if (!Arrays.equals(rawData, other.rawData)) return false;
    if (!type.equals(other.type)) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static final class Builder {

    private SctpChunkType type;
    private byte[] rawData;

    /** */
    public Builder() {}

    private Builder(IllegalSctpChunk obj) {
      this.type = obj.type;
      this.rawData = obj.rawData;
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
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /** @return a new IllegalSctpChunk object. */
    public IllegalSctpChunk build() {
      return new IllegalSctpChunk(this);
    }
  }
}
