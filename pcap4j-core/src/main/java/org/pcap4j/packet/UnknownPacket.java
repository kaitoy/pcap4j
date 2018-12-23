/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UnknownPacket extends SimplePacket {

  /** */
  private static final long serialVersionUID = 8651511568344022477L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownPacket object.
   */
  public static UnknownPacket newPacket(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownPacket(rawData, offset, length);
  }

  private UnknownPacket(byte[] rawData, int offset, int length) {
    super(rawData, offset, length);
  }

  private UnknownPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  protected String modifier() {
    return "";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends org.pcap4j.packet.SimplePacket.Builder {

    /** */
    public Builder() {}

    private Builder(UnknownPacket packet) {
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
    public UnknownPacket build() {
      return new UnknownPacket(this);
    }
  }
}
