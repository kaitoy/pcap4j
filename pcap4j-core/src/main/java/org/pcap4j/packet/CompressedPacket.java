/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class CompressedPacket extends SimplePacket {

  /** */
  private static final long serialVersionUID = 3129881252128550354L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new CompressedPacket object.
   */
  public static CompressedPacket newPacket(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new CompressedPacket(rawData, offset, length);
  }

  private CompressedPacket(byte[] rawData, int offset, int length) {
    super(rawData, offset, length);
  }

  private CompressedPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  protected String modifier() {
    return "Compressed ";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public static final class Builder extends org.pcap4j.packet.SimplePacket.Builder {

    /** */
    public Builder() {}

    private Builder(CompressedPacket packet) {
      super(packet);
    }

    /**
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      setRawData(rawData);
      return this;
    }

    @Override
    public CompressedPacket build() {
      return new CompressedPacket(this);
    }
  }
}
