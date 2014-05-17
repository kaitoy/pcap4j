/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.io.Serializable;
import java.math.BigInteger;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2MpInt implements Serializable {

  /*
   * http://www.ietf.org/rfc/rfc4251.txt
   *
   * Represents multiple precision integers in two's complement format,
   * stored as a string, 8 bits per byte, MSB first.  Negative numbers
   * have the value 1 as the most significant bit of the first byte of
   * the data partition.  If the most significant bit would be set for
   * a positive number, the number MUST be preceded by a zero byte.
   * Unnecessary leading bytes with the value 0 or 255 MUST NOT be
   * included.  The value zero MUST be stored as a string with zero
   * bytes of data.
   */

  /**
   *
   */
  private static final long serialVersionUID = 5539706044412185073L;

  private final int length;
  private final byte[] value;

  /**
   *
   * @param rawData
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public Ssh2MpInt(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The rawData length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = ByteArrays.getInt(rawData, 0);
    if (length < 0) {
      StringBuilder sb = new StringBuilder(120);
      sb.append("A name-list the length of which is longer than 2147483647 is not supported. length: ")
        .append(length & 0xFFFFFFFFL);
      throw new IllegalRawDataException(sb.toString());
    }

    this.value = ByteArrays.getSubArray(rawData, 4, length);
  }

  /**
   *
   * @param value
   */
  public Ssh2MpInt(long value) {
    byte[] valArr = ByteArrays.toByteArray(value);
    if (Byte.MIN_VALUE <= value && Byte.MAX_VALUE <= value) {
      valArr = ByteArrays.getSubArray(valArr, 7);
    }
    else if (Short.MIN_VALUE <= value && value <= Short.MAX_VALUE) {
      valArr = ByteArrays.getSubArray(valArr, 6);
    }
    else if ((Short.MIN_VALUE << 8) <= value && value <= ((Short.MAX_VALUE + 1 << 8) - 1)) {
      valArr = ByteArrays.getSubArray(valArr, 5);
    }
    else if (Integer.MIN_VALUE <= value && value <= Integer.MAX_VALUE) {
      valArr = ByteArrays.getSubArray(valArr, 4);
    }
    else if ((Integer.MIN_VALUE << 8L) <= value && value <= ((Integer.MAX_VALUE + 1L << 8) - 1)) {
      valArr = ByteArrays.getSubArray(valArr, 3);
    }
    else if ((Integer.MIN_VALUE << 16L) <= value && value <= ((Integer.MAX_VALUE + 1L << 16) - 1)) {
      valArr = ByteArrays.getSubArray(valArr, 2);
    }
    else if ((Integer.MIN_VALUE << 24L) <= value && value <= ((Integer.MAX_VALUE + 1L << 24) - 1)) {
      valArr = ByteArrays.getSubArray(valArr, 1);
    }
    this.value = valArr;
    this.length = this.value.length;
  }

  /**
   *
   * @return value of the length field
   */
  public int getLength() {
    return length;
  }

  /**
   *
   * @return value
   */
  public byte[] getValue() {
    return ByteArrays.clone(value);
  }

  /**
   *
   * @return value as BigInteger
   */
  public BigInteger getValueAsBigInteger() {
    return new BigInteger(value);
  }


  /**
   *
   * @return length
   */
  public int length() {
    return length + INT_SIZE_IN_BYTES;
  }

  /**
   *
   * @return rawData
   */
  public byte[] getRawData() {
    byte[] rawData = new byte[length + 4];
    System.arraycopy(ByteArrays.toByteArray(length), 0, rawData, 0, INT_SIZE_IN_BYTES);
    System.arraycopy(value, 0, rawData, INT_SIZE_IN_BYTES, length);
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(50);
    sb.append(getValueAsBigInteger())
      .append(" (")
      .append(ByteArrays.toHexString(value, " "))
      .append(")");
    return sb.toString();
  }

}
