/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
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
public final class IllegalPacket extends AbstractPacket implements IllegalRawDataPacket {

  /**
   *
   */
  private static final long serialVersionUID = -8570543867382087471L;

  private final byte[] rawData;
  private final IllegalRawDataException cause;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param cause cause
   * @return a new IllegalPacket object.
   */
  public static IllegalPacket newPacket(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    if (cause == null) {
      throw new NullPointerException("cause is null.");
    }
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalPacket(rawData, offset, length, cause);
  }

  private IllegalPacket(byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
    this.cause = cause;
  }

  private IllegalPacket(Builder builder) {
    if (
         builder == null
      || builder.rawData == null
      || builder.cause == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.rawData: ").append(builder.rawData)
        .append(" builder.cause").append(builder.cause);
      throw new NullPointerException(sb.toString());
    }

    this.rawData = new byte[builder.rawData.length];
    System.arraycopy(
      builder.rawData, 0, this.rawData, 0, builder.rawData.length
    );
    this.cause = builder.cause;
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
  public IllegalRawDataException getCause() {
    return cause;
  }

  /**
   *
   */
  @Override
  public Builder getBuilder() {
    return new Builder(this);
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
    sb.append("  Cause: ")
      .append(cause)
      .append(ls);

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    IllegalPacket other = (IllegalPacket)obj;
    return    Arrays.equals(rawData, other.rawData)
           && cause.equals(other.cause);
  }

  @Override
  protected int calcHashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + cause.hashCode();
    result = prime * result + Arrays.hashCode(rawData);
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.5
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] rawData = new byte[0];
    private IllegalRawDataException cause;

    /**
     *
     */
    public Builder() {}

    private Builder(IllegalPacket packet) {
      this.rawData = packet.rawData;
      this.cause = packet.cause;
    }

    /**
     * @param rawData rawData
     * @return this Builder object for method chaining.
     */
    public Builder rawData(byte[] rawData) {
      this.rawData = rawData;
      return this;
    }

    /**
     * @param cause cause
     * @return this Builder object for method chaining.
     */
    public Builder cause(IllegalRawDataException cause) {
      this.cause = cause;
      return this;
    }

    @Override
    public IllegalPacket build() {
      return new IllegalPacket(this);
    }

  }

}
