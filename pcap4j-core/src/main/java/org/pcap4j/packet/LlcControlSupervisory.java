/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.packet.namednumber.LlcControlSupervisoryFunction;
import org.pcap4j.util.ByteArrays;

/**
 * The Control field of an LLC header in S-format.
 *
 * <pre>{@code
 *    0     1     2     3     4     5     6     7
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |     receive sequence number             | P/F |
 * |                                         |     |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |      reserved         |supervisory|  0  |  1  |
 * |                       | func bits |     |     |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcControlSupervisory implements LlcControl {

  /** */
  private static final long serialVersionUID = 2248935134729569341L;

  private final byte receiveSequenceNumber;
  private final boolean pfBit;
  private final byte reserved;
  private final LlcControlSupervisoryFunction supervisoryFunction;

  /**
   * @param value value
   * @return a new LlcControlSupervisory object.
   * @throws IllegalRawDataException if parsing the value fails.
   */
  public static LlcControlSupervisory newInstance(short value) throws IllegalRawDataException {
    return new LlcControlSupervisory(value);
  }

  private LlcControlSupervisory(short value) throws IllegalRawDataException {
    if ((value & 0x0300) != 0x0100) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("value & 0x0300 must be 0x0100. value: ")
          .append(ByteArrays.toHexString(value, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.receiveSequenceNumber = (byte) ((value >> 1) & 0x7F);
    if ((value & 0x0001) == 0) {
      this.pfBit = false;
    } else {
      this.pfBit = true;
    }
    this.reserved = (byte) ((value >> 12) & 0x0F);
    this.supervisoryFunction =
        LlcControlSupervisoryFunction.getInstance((byte) ((value >> 10) & 0x03));
  }

  private LlcControlSupervisory(Builder builder) {
    if (builder == null || builder.supervisoryFunction == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.supervisoryFunction: ")
          .append(builder.supervisoryFunction);
      throw new NullPointerException(sb.toString());
    }
    if (builder.receiveSequenceNumber < 0) {
      throw new IllegalArgumentException(
          "receiveSequenceNumber must be positive. receiveSequenceNumber: "
              + builder.receiveSequenceNumber);
    }
    if ((builder.reserved & 0xFF00) != 0) {
      throw new IllegalArgumentException(
          "reserved & 0xFF00 must be 0. reserved: " + builder.reserved);
    }

    this.receiveSequenceNumber = builder.receiveSequenceNumber;
    this.pfBit = builder.pfBit;
    this.reserved = builder.reserved;
    this.supervisoryFunction = builder.supervisoryFunction;
  }

  /** @return receiveSequenceNumber */
  public byte getReceiveSequenceNumber() {
    return receiveSequenceNumber;
  }

  /** @return receiveSequenceNumber */
  public int getReceiveSequenceNumberAsInt() {
    return receiveSequenceNumber;
  }

  /** @return true if the P/F bit is set to 1; otherwise false. */
  public boolean getPfBit() {
    return pfBit;
  }

  /** @return reserved */
  public byte getReserved() {
    return reserved;
  }

  /** @return supervisoryFunction */
  public LlcControlSupervisoryFunction getLlcSupervisoryFunction() {
    return supervisoryFunction;
  }

  @Override
  public int length() {
    return 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[2];
    data[1] = (byte) (receiveSequenceNumber << 1);
    if (pfBit) {
      data[1] |= 0x01;
    }
    data[0] = (byte) (0x01 | (supervisoryFunction.value() << 2) | (reserved << 4));
    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[receive sequence number: ")
        .append(receiveSequenceNumber)
        .append("] [P/F bit: ")
        .append(pfBit ? 1 : 0)
        .append("] [reserved: ")
        .append(reserved)
        .append("] [supervisory function: ")
        .append(supervisoryFunction)
        .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + receiveSequenceNumber;
    result = prime * result + (pfBit ? 1231 : 1237);
    result = prime * result + reserved;
    result = prime * result + supervisoryFunction.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    LlcControlSupervisory other = (LlcControlSupervisory) obj;
    return receiveSequenceNumber == other.receiveSequenceNumber
        && supervisoryFunction.equals(other.supervisoryFunction)
        && reserved == other.reserved
        && pfBit == other.pfBit;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte receiveSequenceNumber;
    private boolean pfBit;
    private byte reserved;
    private LlcControlSupervisoryFunction supervisoryFunction;

    /** */
    public Builder() {}

    private Builder(LlcControlSupervisory ctrl) {
      this.receiveSequenceNumber = ctrl.receiveSequenceNumber;
      this.pfBit = ctrl.pfBit;
      this.reserved = ctrl.reserved;
      this.supervisoryFunction = ctrl.supervisoryFunction;
    }

    /**
     * @param receiveSequenceNumber receiveSequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder receiveSequenceNumber(byte receiveSequenceNumber) {
      this.receiveSequenceNumber = receiveSequenceNumber;
      return this;
    }

    /**
     * @param pfBit pfBit
     * @return this Builder object for method chaining.
     */
    public Builder pfBit(boolean pfBit) {
      this.pfBit = pfBit;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param supervisoryFunction supervisoryFunction
     * @return this Builder object for method chaining.
     */
    public Builder supervisoryFunction(LlcControlSupervisoryFunction supervisoryFunction) {
      this.supervisoryFunction = supervisoryFunction;
      return this;
    }

    /** @return a new LlcControlSupervisory object. */
    public LlcControlSupervisory build() {
      return new LlcControlSupervisory(this);
    }
  }
}
