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
 * @since pcap4j 0.9.11
 */
public final class FragmentedPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -3607736905600980227L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return
   */
  public static FragmentedPacket newPacket(byte[] rawData) {
    return new FragmentedPacket(rawData);
  }

  private FragmentedPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  private FragmentedPacket(Builder builder) {
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
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData;

    /**
     *
     */
    public Builder() {}

    private Builder(FragmentedPacket packet) {
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

    @Override
    public FragmentedPacket build() {
      return new FragmentedPacket(this);
    }

  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[Fragmented data (")
      .append(length())
      .append(" bytes)]")
      .append(ls);
    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append(ls);

    return sb.toString();
  }

}
