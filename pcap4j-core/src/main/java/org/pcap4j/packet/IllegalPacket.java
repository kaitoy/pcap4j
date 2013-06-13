/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.5
 */
public final class IllegalPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -8028013257441150031L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new IllegalPacket object.
   */
  public static IllegalPacket newPacket(byte[] rawData) {
    return new IllegalPacket(rawData);
  }

  private IllegalPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException();
    }
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private IllegalPacket(Builder builder) {
    if (
         builder == null
      || builder.rawData == null
    ) {
      throw new NullPointerException();
    }

    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(
      builder.rawData, 0, this.rawData, 0, builder.rawData.length
    );
  }

  @Override
  public int length() { return rawData.length; }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  /**
   *
   */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.5
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData = new byte[0];

    /**
     *
     */
    public Builder() {}

    private Builder(IllegalPacket packet) {
      rawData = packet.rawData;
    }

    /**
     *
     * @param rawData
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

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[Illegal Packet (")
      .append(length())
      .append(" bytes)]")
      .append(ls);
    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append(ls);

    return sb.toString();
  }

}
