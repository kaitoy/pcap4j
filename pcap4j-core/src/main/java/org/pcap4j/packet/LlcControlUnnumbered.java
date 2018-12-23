/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.LlcPacket.LlcControl;
import org.pcap4j.packet.namednumber.LlcControlModifierFunction;
import org.pcap4j.util.ByteArrays;

/**
 * The Control field of an LLC header in U-format.
 *
 * <pre>{@code
 *    0     1     2     3     4     5     6     7
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |    modifier     | P/F | modifier  |  1  |  1  |
 * |    func bits    |     | func bits |     |     |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcControlUnnumbered implements LlcControl {

  /** */
  private static final long serialVersionUID = 8688698899763120721L;

  private final LlcControlModifierFunction modifierFunction;
  private final boolean pfBit;

  /**
   * @param value value
   * @return a new LlcControlSupervisory object.
   * @throws IllegalRawDataException if parsing the value fails.
   */
  public static LlcControlUnnumbered newInstance(byte value) throws IllegalRawDataException {
    return new LlcControlUnnumbered(value);
  }

  private LlcControlUnnumbered(byte value) throws IllegalRawDataException {
    if ((value & 0x03) != 0x03) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Both the lsb and the second lsb of the value must be 1. value: ")
          .append(ByteArrays.toHexString(value, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.modifierFunction = LlcControlModifierFunction.getInstance((byte) ((value >> 2) & 0x3B));
    if ((value & 0x10) == 0) {
      this.pfBit = false;
    } else {
      this.pfBit = true;
    }
  }

  private LlcControlUnnumbered(Builder builder) {
    if (builder == null || builder.modifierFunction == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.modifierFunction: ")
          .append(builder.modifierFunction);
      throw new NullPointerException(sb.toString());
    }

    this.modifierFunction = builder.modifierFunction;
    this.pfBit = builder.pfBit;
  }

  /** @return modifierFunction */
  public LlcControlModifierFunction getModifierFunction() {
    return modifierFunction;
  }

  /** @return true if the P/F bit is set to 1; otherwise false. */
  public boolean getPfBit() {
    return pfBit;
  }

  @Override
  public int length() {
    return 1;
  }

  @Override
  public byte[] getRawData() {
    byte[] data = new byte[1];
    data[0] = (byte) (0x03 | (modifierFunction.value() << 2));
    if (pfBit) {
      data[0] |= 0x10;
    }
    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[modifier function: ")
        .append(modifierFunction)
        .append("] [P/F bit: ")
        .append(pfBit ? 1 : 0)
        .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + modifierFunction.hashCode();
    result = prime * result + (pfBit ? 1231 : 1237);
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
    LlcControlUnnumbered other = (LlcControlUnnumbered) obj;
    return modifierFunction.equals(other.modifierFunction) && pfBit == other.pfBit;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private LlcControlModifierFunction modifierFunction;
    private boolean pfBit;

    /** */
    public Builder() {}

    private Builder(LlcControlUnnumbered ctrl) {
      this.modifierFunction = ctrl.modifierFunction;
      this.pfBit = ctrl.pfBit;
    }

    /**
     * @param modifierFunction modifierFunction
     * @return this Builder object for method chaining.
     */
    public Builder modifierFunction(LlcControlModifierFunction modifierFunction) {
      this.modifierFunction = modifierFunction;
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

    /** @return a new LlcControlSupervisory object. */
    public LlcControlUnnumbered build() {
      return new LlcControlUnnumbered(this);
    }
  }
}
