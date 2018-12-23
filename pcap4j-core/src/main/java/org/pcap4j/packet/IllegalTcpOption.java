/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class IllegalTcpOption implements TcpOption {

  /** */
  private static final long serialVersionUID = 4128600756828920489L;

  private final TcpOptionKind kind;
  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IllegalTcpOption object.
   */
  public static IllegalTcpOption newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalTcpOption(rawData, offset, length);
  }

  private IllegalTcpOption(byte[] rawData, int offset, int length) {
    this.kind = TcpOptionKind.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalTcpOption(Builder builder) {
    if (builder == null || builder.kind == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.kind: ")
          .append(builder.kind)
          .append(" builder.rawData: ")
          .append(builder.rawData);
      throw new NullPointerException(sb.toString());
    }

    this.kind = builder.kind;
    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(builder.rawData, 0, this.rawData, 0, builder.rawData.length);
  }

  @Override
  public TcpOptionKind getKind() {
    return kind;
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
    sb.append("[Kind: ")
        .append(kind)
        .append("] [Illegal Raw Data: 0x")
        .append(ByteArrays.toHexString(rawData, ""))
        .append("]");
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

    IllegalTcpOption other = (IllegalTcpOption) obj;
    return kind.equals(other.kind) && Arrays.equals(other.rawData, rawData);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + kind.hashCode();
    result = 31 * result + Arrays.hashCode(rawData);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class Builder {

    private TcpOptionKind kind;
    private byte[] rawData;

    /** */
    public Builder() {}

    private Builder(IllegalTcpOption option) {
      this.kind = option.kind;
      this.rawData = option.rawData;
    }

    /**
     * @param kind kind
     * @return this Builder object for method chaining.
     */
    public Builder kind(TcpOptionKind kind) {
      this.kind = kind;
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

    /** @return a new IllegalTcpOption object. */
    public IllegalTcpOption build() {
      return new IllegalTcpOption(this);
    }
  }
}
