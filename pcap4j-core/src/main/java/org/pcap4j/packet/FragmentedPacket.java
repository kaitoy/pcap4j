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
 * @since pcap4j 0.9.11
 */
public final class FragmentedPacket extends SimplePacket {

  /** */
  private static final long serialVersionUID = 8065880017691703511L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new FragmentedPacket object.
   */
  public static FragmentedPacket newPacket(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new FragmentedPacket(rawData, offset, length);
  }

  private FragmentedPacket(byte[] rawData, int offset, int length) {
    super(rawData, offset, length);
  }

  private FragmentedPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  protected String modifier() {
    return "Fragmented ";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends org.pcap4j.packet.SimplePacket.Builder {

    /** */
    public Builder() {}

    private Builder(FragmentedPacket packet) {
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
    public FragmentedPacket build() {
      return new FragmentedPacket(this);
    }
  }
}
