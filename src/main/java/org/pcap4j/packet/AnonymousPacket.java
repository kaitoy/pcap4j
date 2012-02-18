/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public
final class AnonymousPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4601589840627505036L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return
   */
  public static AnonymousPacket newPacket(byte[] rawData) {
    return new AnonymousPacket(rawData);
  }

  private AnonymousPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException();
    }
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private AnonymousPacket(Builder builder) {
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
  public boolean isValid() { return true; }

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
   * @since pcap4j 0.9.1
   */
  public static final class Builder implements Packet.Builder {

    private byte[] rawData = new byte[0];

    /**
     *
     */
    public Builder() {}

    private Builder(AnonymousPacket packet) {
      rawData = packet.rawData;
    }

    /**
     *
     * @param rawData
     * @return
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    public AnonymousPacket build() {
      return new AnonymousPacket(this);
    }

  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();

    sb.append("[data (")
      .append(length())
      .append(" bytes)]\n");
    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append("\n");

    return sb.toString();
  }

}
