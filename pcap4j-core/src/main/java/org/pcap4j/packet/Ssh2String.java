/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2String implements Serializable {

  /*
   * http://www.ietf.org/rfc/rfc4251.txt
   *
   * Arbitrary length binary string.  Strings are allowed to contain
   * arbitrary binary data, including null characters and 8-bit
   * characters.  They are stored as a uint32 containing its length
   * (number of bytes that follow) and zero (= empty string) or more
   * bytes that are the value of the string.  Terminating null
   * characters are not used.
   *
   * Strings are also used to store text.  In that case, US-ASCII is
   * used for internal names, and ISO-10646 UTF-8 for text that might
   * be displayed to the user.  The terminating null character SHOULD
   * NOT normally be stored in the string.  For example: the US-ASCII
   * string "testing" is represented as 00 00 00 07 t e s t i n g.  The
   * UTF-8 mapping does not alter the encoding of US-ASCII characters.
   */

  /**
   *
   */
  private static final long serialVersionUID = -1591381991570120515L;

  private final int length;
  private final byte[] string;

  /**
   *
   * @param rawData
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public Ssh2String(byte[] rawData) throws IllegalRawDataException {
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

    this.string = ByteArrays.getSubArray(rawData, 4, length);
  }

  /**
   *
   * @param str
   */
  public Ssh2String(String str) {
    if (str == null) {
      throw new NullPointerException();
    }

    try {
      this.string = str.getBytes("UTF-8");
      this.length = string.length;
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError("Never get here.");
    }
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
   * @return string
   */
  public byte[] getString() {
    return ByteArrays.clone(string);
  }

  /**
   * @return string
   */
  public String getStringAsString() {
    try {
      return new String(string, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError("Never get here.");
    }
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
    System.arraycopy(string, 0, rawData, INT_SIZE_IN_BYTES, length);
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(50);
    sb.append(getStringAsString())
      .append(" (")
      .append(ByteArrays.toHexString(string, " "))
      .append(")");
    return sb.toString();
  }

}
