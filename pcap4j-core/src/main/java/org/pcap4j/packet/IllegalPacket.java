/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.5
 */
public final class IllegalPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -8028013257441150031L;

  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IllegalPacket object.
   */
  public static IllegalPacket newPacket(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalPacket(rawData, offset, length);
  }

  private IllegalPacket(byte[] rawData, int offset, int length) {
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  private IllegalPacket(Builder builder) {
    if (builder == null || builder.rawData == null) {
      throw new NullPointerException();
    }

    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(builder.rawData, 0, this.rawData, 0, builder.rawData.length);
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

  /** */
  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[Illegal Packet (").append(length()).append(" bytes)]").append(ls);
    sb.append("  Hex stream: ").append(ByteArrays.toHexString(rawData, " ")).append(ls);

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
    IllegalPacket other = (IllegalPacket) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  @Override
  protected int calcHashCode() {
    return Arrays.hashCode(rawData);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.5
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData = new byte[0];

    /** */
    public Builder() {}

    private Builder(IllegalPacket packet) {
      rawData = packet.rawData;
    }

    /**
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    @Override
    public IllegalPacket build() {
      return new IllegalPacket(this);
    }
  }
}
