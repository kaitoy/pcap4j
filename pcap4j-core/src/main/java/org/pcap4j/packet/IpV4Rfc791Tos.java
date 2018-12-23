/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.namednumber.IpV4TosPrecedence;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4Rfc791Tos implements IpV4Tos {

  /** */
  private static final long serialVersionUID = 1760697525836662144L;

  /* http://www.ietf.org/rfc/rfc791.txt
   *
   *     0     1     2     3     4     5     6     7
   *  +-----+-----+-----+-----+-----+-----+-----+-----+
   *  |                 |     |     |     |     |     |
   *  |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
   *  |                 |     |     |     |     |     |
   *  +-----+-----+-----+-----+-----+-----+-----+-----+
   */

  private final IpV4TosPrecedence precedence;
  private final boolean lowDelay;
  private final boolean highThroughput;
  private final boolean highReliability;
  private final boolean seventhBit;
  private final boolean eighthBit;

  /**
   * @param value value
   * @return a new IpV4Rfc791Tos object.
   */
  public static IpV4Rfc791Tos newInstance(byte value) {
    return new IpV4Rfc791Tos(value);
  }

  private IpV4Rfc791Tos(byte value) {

    this.precedence = IpV4TosPrecedence.getInstance((byte) ((value & 0xE0) >> 5));
    this.lowDelay = (value & 0x10) != 0;
    this.highThroughput = (value & 0x08) != 0;
    this.highReliability = (value & 0x04) != 0;
    this.seventhBit = (value & 0x02) != 0;
    this.eighthBit = (value & 0x01) != 0;
  }

  private IpV4Rfc791Tos(Builder builder) {
    if (builder == null || builder.precedence == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder")
          .append(builder)
          .append(" builder.precedence: ")
          .append(builder.precedence);
      throw new NullPointerException(sb.toString());
    }

    this.precedence = builder.precedence;
    this.lowDelay = builder.lowDelay;
    this.highThroughput = builder.highThroughput;
    this.highReliability = builder.highReliability;
    this.seventhBit = builder.seventhBit;
    this.eighthBit = builder.eighthBit;
  }

  /** @return precedence */
  public IpV4TosPrecedence getPrecedence() {
    return precedence;
  }

  /** @return lowDelay */
  public boolean isLowDelay() {
    return lowDelay;
  }

  /** @return highThroughput */
  public boolean isHighThroughput() {
    return highThroughput;
  }

  /** @return highReliability */
  public boolean isHighReliability() {
    return highReliability;
  }

  /** @return seventhBit */
  public boolean getSeventhBit() {
    return seventhBit;
  }

  /** @return eighthBit */
  public boolean getEighthBit() {
    return eighthBit;
  }

  public byte value() {
    byte value = (byte) (precedence.value() << 5);
    if (lowDelay) {
      value = (byte) (value | 0x10);
    }
    if (highThroughput) {
      value = (byte) (value | 0x08);
    }
    if (highReliability) {
      value = (byte) (value | 0x04);
    }
    if (seventhBit) {
      value = (byte) (value | 0x02);
    }
    if (eighthBit) {
      value = (byte) (value | 0x01);
    }
    return value;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[precedence: ")
        .append(precedence)
        .append("] [lowDelay: ")
        .append(lowDelay)
        .append("] [highThroughput: ")
        .append(highThroughput)
        .append("] [highReliability: ")
        .append(highReliability)
        .append("] [seventhBit: ")
        .append(seventhBit ? 1 : 0)
        .append("] [eighthBit: ")
        .append(eighthBit ? 1 : 0)
        .append("]");

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    return (getClass().cast(obj)).value() == this.value();
  }

  @Override
  public int hashCode() {
    return value();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder {

    private IpV4TosPrecedence precedence;
    private boolean lowDelay;
    private boolean highThroughput;
    private boolean highReliability;
    private boolean seventhBit;
    private boolean eighthBit;

    /** */
    public Builder() {}

    private Builder(IpV4Rfc791Tos tos) {
      this.precedence = tos.precedence;
      this.lowDelay = tos.lowDelay;
      this.highThroughput = tos.highThroughput;
      this.highReliability = tos.highReliability;
      this.seventhBit = tos.seventhBit;
      this.eighthBit = tos.eighthBit;
    }

    /**
     * @param precedence precedence
     * @return this Builder object for method chaining.
     */
    public Builder precedence(IpV4TosPrecedence precedence) {
      this.precedence = precedence;
      return this;
    }

    /**
     * @param lowDelay lowDelay
     * @return this Builder object for method chaining.
     */
    public Builder lowDelay(boolean lowDelay) {
      this.lowDelay = lowDelay;
      return this;
    }

    /**
     * @param highThroughput highThroughput
     * @return this Builder object for method chaining.
     */
    public Builder highThroughput(boolean highThroughput) {
      this.highThroughput = highThroughput;
      return this;
    }

    /**
     * @param highRelibility highRelibility
     * @return this Builder object for method chaining.
     */
    public Builder highReliability(boolean highRelibility) {
      this.highReliability = highRelibility;
      return this;
    }

    /**
     * @param seventhBit seventhBit
     * @return this Builder object for method chaining.
     */
    public Builder seventhBit(boolean seventhBit) {
      this.seventhBit = seventhBit;
      return this;
    }

    /**
     * @param eighthBit eighthBit
     * @return this Builder object for method chaining.
     */
    public Builder eighthBit(boolean eighthBit) {
      this.eighthBit = eighthBit;
      return this;
    }

    /** @return a new IpV4Rfc791Tos object. */
    public IpV4Rfc791Tos build() {
      return new IpV4Rfc791Tos(this);
    }
  }
}
