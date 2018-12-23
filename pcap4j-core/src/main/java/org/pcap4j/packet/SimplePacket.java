/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
abstract class SimplePacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -1565433651791063490L;

  private final byte[] rawData;

  protected SimplePacket(byte[] rawData, int offset, int length) {
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  protected SimplePacket(Builder builder) {
    if (builder == null || builder.rawData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.rawData: ").append(builder.rawData);
      throw new NullPointerException(sb.toString());
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

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("[")
        .append(modifier())
        .append("data (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
    sb.append("  Hex stream: ").append(ByteArrays.toHexString(rawData, " ")).append(ls);

    return sb.toString();
  }

  protected abstract String modifier();

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    SimplePacket other = (SimplePacket) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  @Override
  protected int calcHashCode() {
    return Arrays.hashCode(rawData);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.4.0
   */
  public abstract static class Builder extends AbstractBuilder {

    private byte[] rawData;

    /** */
    public Builder() {}

    protected Builder(SimplePacket packet) {
      rawData = packet.rawData;
    }

    /** @param rawData rawData */
    protected void setRawData(byte[] rawData) {
      this.rawData = rawData;
    }
  }
}
