/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.util.ByteArrays;

/**
 * The Control field of an LLC header in I-format.
 *
 * <pre>{@code
 *    0     1     2     3     4     5     6     7
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |     receive sequence number             | P/F |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |        send sequence number             |  0  |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcControlInformation implements LlcControl {

  /** */
  private static final long serialVersionUID = -4014592337107864662L;

  private final byte receiveSequenceNumber;
  private final boolean pfBit;
  private final byte sendSequenceNumber;

  /**
   * @param value value
   * @return a new LlcControlInformation object.
   * @throws IllegalRawDataException if parsing the value fails.
   */
  public static LlcControlInformation newInstance(short value) throws IllegalRawDataException {
    return new LlcControlInformation(value);
  }

  private LlcControlInformation(short value) throws IllegalRawDataException {
    if ((value & 0x0100) != 0) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("value & 0x0100 must be 0. value: ").append(ByteArrays.toHexString(value, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.receiveSequenceNumber = (byte) ((value >> 1) & 0x7F);
    if ((value & 0x0001) == 0) {
      this.pfBit = false;
    } else {
      this.pfBit = true;
    }
    this.sendSequenceNumber = (byte) ((value >> 9) & 0x7F);
  }

  private LlcControlInformation(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder must not be null.");
    }
    if (builder.receiveSequenceNumber < 0) {
      throw new IllegalArgumentException(
          "receiveSequenceNumber must be positive. receiveSequenceNumber: "
              + builder.receiveSequenceNumber);
    }
    if (builder.sendSequenceNumber < 0) {
      throw new IllegalArgumentException(
          "sendSequenceNumber must be positive. sendSequenceNumber: " + builder.sendSequenceNumber);
    }

    this.receiveSequenceNumber = builder.receiveSequenceNumber;
    this.pfBit = builder.pfBit;
    this.sendSequenceNumber = builder.sendSequenceNumber;
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

  /** @return sendSequenceNumber */
  public byte getSendSequenceNumber() {
    return sendSequenceNumber;
  }

  /** @return sendSequenceNumber */
  public int getSendSequenceNumberAsInt() {
    return sendSequenceNumber;
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
    data[0] = (byte) (sendSequenceNumber << 1);
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
        .append("] [send sequence number: ")
        .append(sendSequenceNumber)
        .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + receiveSequenceNumber;
    result = prime * result + (pfBit ? 1231 : 1237);
    result = prime * result + sendSequenceNumber;
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
    LlcControlInformation other = (LlcControlInformation) obj;
    return receiveSequenceNumber == other.receiveSequenceNumber
        && sendSequenceNumber == other.sendSequenceNumber
        && pfBit == other.pfBit;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private byte receiveSequenceNumber;
    private boolean pfBit;
    private byte sendSequenceNumber;

    /** */
    public Builder() {}

    private Builder(LlcControlInformation ctrl) {
      this.receiveSequenceNumber = ctrl.receiveSequenceNumber;
      this.pfBit = ctrl.pfBit;
      this.sendSequenceNumber = ctrl.sendSequenceNumber;
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
     * @param sendSequenceNumber sendSequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sendSequenceNumber(byte sendSequenceNumber) {
      this.sendSequenceNumber = sendSequenceNumber;
      return this;
    }

    /** @return a new LlcControlInformation object. */
    public LlcControlInformation build() {
      return new LlcControlInformation(this);
    }
  }
}
