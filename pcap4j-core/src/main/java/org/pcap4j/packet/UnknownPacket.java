/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class UnknownPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4601589840627505036L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new UnknownPacket object.
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static UnknownPacket newPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new UnknownPacket(rawData);
  }

  private UnknownPacket(byte[] rawData) {
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private UnknownPacket(Builder builder) {
    if (
         builder == null
      || builder.rawData == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.rawData: ").append(builder.rawData);
      throw new NullPointerException(sb.toString());
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

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData;

    /**
     *
     */
    public Builder() {}

    private Builder(UnknownPacket packet) {
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
    public UnknownPacket build() {
      return new UnknownPacket(this);
    }

  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[data (")
      .append(length())
      .append(" bytes)]")
      .append(ls);
    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append(ls);

    return sb.toString();
  }

}
