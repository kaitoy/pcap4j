/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import java.nio.ByteOrder;
import org.pcap4j.util.ByteArrays;

/**
 * Sequence Control field of an IEEE802.11 frame.
 *
 * <pre>{@code
 *    0     1     2     3     4     5     6     7
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |    Fragment Number    |                       |
 * +-----+-----+-----+-----+                       |
 * |               Sequence Number                 |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11SequenceControl implements Serializable {

  /** */
  private static final long serialVersionUID = 8383319258993027L;

  private final byte fragmentNumber;
  private final short sequenceNumber;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11SequenceControl object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11SequenceControl newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11SequenceControl(rawData, offset, length);
  }

  private Dot11SequenceControl(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 2) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a Dot11SequenceControl (")
          .append(2)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.fragmentNumber = (byte) (rawData[offset] & 0x0F);
    this.sequenceNumber =
        (short) ((ByteArrays.getShort(rawData, offset, ByteOrder.LITTLE_ENDIAN) >> 4) & 0x0FFF);
  }

  private Dot11SequenceControl(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder is null.");
    }
    if ((builder.fragmentNumber & 0xF0) != 0) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("(builder.fragmentNumber & 0xF0) must be zero. builder.fragmentNumber: ")
          .append(builder.fragmentNumber);
      throw new IllegalArgumentException(sb.toString());
    }
    if ((builder.sequenceNumber & 0xF000) != 0) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("(builder.sequenceNumber & 0xF000) must be zero. builder.sequenceNumber: ")
          .append(builder.sequenceNumber);
      throw new IllegalArgumentException(sb.toString());
    }

    this.fragmentNumber = builder.fragmentNumber;
    this.sequenceNumber = builder.sequenceNumber;
  }

  /** @return fragmentNumber */
  public byte getFragmentNumber() {
    return fragmentNumber;
  }

  /** @return fragmentNumber */
  public int getFragmentNumberAsInt() {
    return fragmentNumber;
  }

  /** @return sequenceNumber */
  public short getSequenceNumber() {
    return sequenceNumber;
  }

  /** @return sequenceNumber */
  public int getSequenceNumberAsInt() {
    return sequenceNumber;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = ByteArrays.toByteArray((short) (sequenceNumber << 4), ByteOrder.LITTLE_ENDIAN);
    data[0] |= fragmentNumber;
    return data;
  }

  /** @return length */
  public int length() {
    return 2;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(250);

    sb.append("[Fragment Number: ")
        .append(getFragmentNumberAsInt())
        .append(", Sequence Number: ")
        .append(getSequenceNumberAsInt())
        .append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + fragmentNumber;
    result = prime * result + sequenceNumber;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11SequenceControl other = (Dot11SequenceControl) obj;
    if (fragmentNumber != other.fragmentNumber) return false;
    if (sequenceNumber != other.sequenceNumber) return false;
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder {

    private byte fragmentNumber;
    private short sequenceNumber;

    /** */
    public Builder() {}

    private Builder(Dot11SequenceControl obj) {
      this.fragmentNumber = obj.fragmentNumber;
      this.sequenceNumber = obj.sequenceNumber;
    }

    /**
     * @param fragmentNumber fragmentNumber. The value is between 0 and 15 (inclusive).
     * @return this Builder object for method chaining.
     */
    public Builder fragmentNumber(byte fragmentNumber) {
      this.fragmentNumber = fragmentNumber;
      return this;
    }

    /**
     * @param sequenceNumber sequenceNumber. The value is between 0 and 4095 (inclusive).
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(short sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    /** @return a new Dot11SequenceControl object. */
    public Dot11SequenceControl build() {
      return new Dot11SequenceControl(this);
    }
  }
}
