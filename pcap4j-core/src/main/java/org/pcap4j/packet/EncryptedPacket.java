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
public final class EncryptedPacket extends SimplePacket {

  /** */
  private static final long serialVersionUID = 1942694224438957128L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new EncryptedPacket object.
   */
  public static EncryptedPacket newPacket(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new EncryptedPacket(rawData, offset, length);
  }

  private EncryptedPacket(byte[] rawData, int offset, int length) {
    super(rawData, offset, length);
  }

  private EncryptedPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  protected String modifier() {
    return "Encrypted ";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public static final class Builder extends org.pcap4j.packet.SimplePacket.Builder {

    /** */
    public Builder() {}

    private Builder(EncryptedPacket packet) {
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
    public EncryptedPacket build() {
      return new EncryptedPacket(this);
    }
  }
}
