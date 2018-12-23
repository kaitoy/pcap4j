/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
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

  /** */
  private static final long serialVersionUID = -1591381991570120515L;

  private final int length;
  private final byte[] string;

  /**
   * Constructor. This method validates the arguments by {@link ByteArrays#validateBounds(byte[],
   * int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public Ssh2String(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    if (length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The rawData length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = ByteArrays.getInt(rawData, offset);
    if (this.length < 0) {
      StringBuilder sb = new StringBuilder(120);
      sb.append("A string the length of which is longer than 2147483647 is not supported. length: ")
          .append(this.length & 0xFFFFFFFFL);
      throw new IllegalRawDataException(sb.toString());
    }
    if (length - 4 < this.length) {
      StringBuilder sb = new StringBuilder(110);
      sb.append("The data is too short to build an Ssh2String (")
          .append(this.length + 4)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.string = ByteArrays.getSubArray(rawData, 4 + offset, this.length);
  }

  /** @param str str */
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

  /** @return value of the length field */
  public int getLength() {
    return length;
  }

  /** @return string */
  public byte[] getString() {
    return ByteArrays.clone(string);
  }

  /** @return string */
  public String getStringAsString() {
    try {
      return new String(string, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError("Never get here.");
    }
  }

  /** @return length */
  public int length() {
    return length + INT_SIZE_IN_BYTES;
  }

  /** @return rawData */
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

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    Ssh2String other = (Ssh2String) obj;
    return length == other.length && Arrays.equals(string, other.string);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(string);
    return result;
  }
}
