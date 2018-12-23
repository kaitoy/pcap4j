/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.namednumber.IpV4TosPrecedence;
import org.pcap4j.packet.namednumber.IpV4TosTos;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4Rfc1349Tos implements IpV4Tos {

  /** */
  private static final long serialVersionUID = 1760697525836662144L;

  /* http://www.ietf.org/rfc/rfc1349.txt
   *
   *    0     1     2     3     4     5     6     7
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   * |                 |                       |     |
   * |   PRECEDENCE    |          TOS          | MBZ |
   * |                 |                       |     |
   * +-----+-----+-----+-----+-----+-----+-----+-----+
   */

  private final IpV4TosPrecedence precedence;
  private final IpV4TosTos tos;
  private final boolean mbz;

  /**
   * @param value value
   * @return a new IpV4Rfc1349Tos object.
   */
  public static IpV4Rfc1349Tos newInstance(byte value) {
    return new IpV4Rfc1349Tos(value);
  }

  private IpV4Rfc1349Tos(byte value) {
    this.precedence = IpV4TosPrecedence.getInstance((byte) ((value & 0xE0) >> 5));
    this.tos = IpV4TosTos.getInstance((byte) (0x0F & (value >> 1)));
    this.mbz = (value & 0x01) != 0;
  }

  private IpV4Rfc1349Tos(Builder builder) {
    if (builder == null || builder.precedence == null || builder.tos == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder")
          .append(builder)
          .append(" builder.precedence: ")
          .append(builder.precedence)
          .append(" builder.tos: ")
          .append(builder.tos);
      throw new NullPointerException(sb.toString());
    }

    this.precedence = builder.precedence;
    this.tos = builder.tos;
    this.mbz = builder.mbz;
  }

  /** @return precedence */
  public IpV4TosPrecedence getPrecedence() {
    return precedence;
  }

  /** @return tos */
  public IpV4TosTos getTos() {
    return tos;
  }

  /** @return mbz */
  public boolean mbz() {
    return mbz;
  }

  public byte value() {
    byte value = (byte) (precedence.value() << 5);
    value = (byte) (value | tos.value() << 1);
    if (mbz) {
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
        .append("] [tos: ")
        .append(tos)
        .append("] [mbz: ")
        .append(mbz ? 1 : 0)
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
    private IpV4TosTos tos;
    private boolean mbz;

    /** */
    public Builder() {}

    private Builder(IpV4Rfc1349Tos tos) {
      this.precedence = tos.precedence;
      this.tos = tos.tos;
      this.mbz = tos.mbz;
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
     * @param tos tos
     * @return this Builder object for method chaining.
     */
    public Builder tos(IpV4TosTos tos) {
      this.tos = tos;
      return this;
    }

    /**
     * @param mbz mbz
     * @return this Builder object for method chaining.
     */
    public Builder mbz(boolean mbz) {
      this.mbz = mbz;
      return this;
    }

    /** @return a new IpV4Rfc1349Tos object. */
    public IpV4Rfc1349Tos build() {
      return new IpV4Rfc1349Tos(this);
    }
  }
}
