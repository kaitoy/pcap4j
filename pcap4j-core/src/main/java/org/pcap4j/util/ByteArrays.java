/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import static java.nio.ByteOrder.*;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteOrder;
import java.util.regex.Pattern;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ByteArrays {

  /**
   *
   */
  public static final int BYTE_SIZE_IN_BYTES = 1;

  /**
   *
   */
  public static final int SHORT_SIZE_IN_BYTES = 2;

  /**
   *
   */
  public static final int INT_SIZE_IN_BYTES = 4;

  /**
   *
   */
  public static final int LONG_SIZE_IN_BYTES = 8;

  /**
   *
   */
  public static final int INET4_ADDRESS_SIZE_IN_BYTES = 4;

  /**
   *
   */
  public static final int INET6_ADDRESS_SIZE_IN_BYTES = 16;

  /**
   *
   */
  public static final int BYTE_SIZE_IN_BITS = 8;

  private static final Pattern NO_SEPARATOR_HEX_STRING_PATTERN
    = Pattern.compile("\\A([0-9a-fA-F][0-9a-fA-F])+\\z");

  private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

  private ByteArrays() { throw new AssertionError(); }

  /**
   *
   * @param array array
   * @return a new array containing specified array's elements in reverse order.
   */
  public static byte[] reverse(byte[] array) {
    byte[] rarray = new byte[array.length];
    for (int i = 0; i < array.length; i++) {
      rarray[i] = array[array.length - i - 1];
    }
    return rarray;
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return byte value.
   */
  public static byte getByte(byte[] array, int offset) {
    validateBounds(array, offset, BYTE_SIZE_IN_BYTES);
    return array[offset];
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(byte value) {
    return new byte[] { value };
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(byte value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return short value
   */
  public static short getShort(byte[] array, int offset) {
    return getShort(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return short value
   */
  public static short getShort(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, SHORT_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return (short)(
                  ((       array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1))
                | ((0xFF & array[offset    ])                           )
              );
    }
    else {
      return (short)(
                  ((       array[offset    ]) << (BYTE_SIZE_IN_BITS * 1))
                | ((0xFF & array[offset + 1])                           )
              );
    }
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(short value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(short value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {
               (byte)(value                         ),
               (byte)(value >> BYTE_SIZE_IN_BITS * 1)
             };
    }
    else {
      return new byte[] {
               (byte)(value >> BYTE_SIZE_IN_BITS * 1),
               (byte)(value                         )
             };
    }
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(short value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(short value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return int value.
   */
  public static int getInt(byte[] array, int offset) {
    return getInt(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return int value.
   */
  public static int getInt(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, INT_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return ((       array[offset + 3]) << (BYTE_SIZE_IN_BITS * 3))
           | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 2))
           | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1))
           | ((0xFF & array[offset    ])                           );
    }
    else {
      return ((       array[offset    ]) << (BYTE_SIZE_IN_BITS * 3))
           | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 2))
           | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 1))
           | ((0xFF & array[offset + 3])                           );
    }
  }

  /**
   * @param array array
   * @param offset offset
   * @param length length
   * @return int value.
   */
  public static int getInt(byte[] array, int offset, int length) {
    return getInt(array, offset, length, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param array array
   * @param offset offset
   * @param length length
   * @param bo bo
   * @return int value.
   */
  public static int getInt(byte[] array, int offset, int length, ByteOrder bo) {
    validateBounds(array, offset, length);
    if (length > INT_SIZE_IN_BYTES) {
      StringBuilder sb
        = new StringBuilder(30)
            .append("length must be equal or less than ")
            .append(INT_SIZE_IN_BYTES)
            .append(", but is: ")
            .append(length);
      throw new IllegalArgumentException(sb.toString());
    }

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    int value = 0;
    if (bo.equals(LITTLE_ENDIAN)) {
      for (int i = offset + length - 1; i >= offset; i--) {
        value <<= BYTE_SIZE_IN_BITS;
        value |= 0xFF & array[i];
      }
    }
    else {
      for (int i = offset; i < offset + length; i++) {
        value <<= BYTE_SIZE_IN_BITS;
        value |= 0xFF & array[i];
      }
    }
    return value;
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(int value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(int value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {
               (byte)(value                         ),
               (byte)(value >> BYTE_SIZE_IN_BITS * 1),
               (byte)(value >> BYTE_SIZE_IN_BITS * 2),
               (byte)(value >> BYTE_SIZE_IN_BITS * 3),
             };
    }
    else {
      return new byte[] {
               (byte)(value >> BYTE_SIZE_IN_BITS * 3),
               (byte)(value >> BYTE_SIZE_IN_BITS * 2),
               (byte)(value >> BYTE_SIZE_IN_BITS * 1),
               (byte)(value                         )
             };
    }
  }

  /**
   * @param value value
   * @param length length
   * @return byte array
   */
  public static byte[] toByteArray(int value, int length) {
    return toByteArray(value, length, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param length length
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(int value, int length, ByteOrder bo) {
    if (length > INT_SIZE_IN_BYTES) {
      StringBuilder sb
        = new StringBuilder(30)
            .append("length must be equal or less than ")
            .append(INT_SIZE_IN_BYTES)
            .append(", but is: ")
            .append(length);
      throw new IllegalArgumentException(sb.toString());
    }

    byte[] arr = new byte[length];
    if (bo.equals(LITTLE_ENDIAN)) {
      for (int i = 0; i < length; i++) {
        arr[length - i - 1] = (byte)(value >> BYTE_SIZE_IN_BITS * i);
      }
    }
    else {
      for (int i = 0; i < length; i++) {
        arr[i] = (byte)(value >> BYTE_SIZE_IN_BITS * i);
      }
    }

    return arr;
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(int value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(int value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return long value
   */
  public static long getLong(byte[] array, int offset) {
    return getLong(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return long value
   */
  public static long getLong(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, LONG_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return ((  (long)array[offset + 7]) << (BYTE_SIZE_IN_BITS * 7))
           | ((0xFFL & array[offset + 6]) << (BYTE_SIZE_IN_BITS * 6))
           | ((0xFFL & array[offset + 5]) << (BYTE_SIZE_IN_BITS * 5))
           | ((0xFFL & array[offset + 4]) << (BYTE_SIZE_IN_BITS * 4))
           | ((0xFFL & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 3))
           | ((0xFFL & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 2))
           | ((0xFFL & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1))
           | ((0xFFL & array[offset    ])                           );
    }
    else {
      return ((  (long)array[offset    ]) << (BYTE_SIZE_IN_BITS * 7))
           | ((0xFFL & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 6))
           | ((0xFFL & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 5))
           | ((0xFFL & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 4))
           | ((0xFFL & array[offset + 4]) << (BYTE_SIZE_IN_BITS * 3))
           | ((0xFFL & array[offset + 5]) << (BYTE_SIZE_IN_BITS * 2))
           | ((0xFFL & array[offset + 6]) << (BYTE_SIZE_IN_BITS * 1))
           | ((0xFFL & array[offset + 7])                           );
    }
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(long value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(long value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {
               (byte)(value                         ),
               (byte)(value >> BYTE_SIZE_IN_BITS * 1),
               (byte)(value >> BYTE_SIZE_IN_BITS * 2),
               (byte)(value >> BYTE_SIZE_IN_BITS * 3),
               (byte)(value >> BYTE_SIZE_IN_BITS * 4),
               (byte)(value >> BYTE_SIZE_IN_BITS * 5),
               (byte)(value >> BYTE_SIZE_IN_BITS * 6),
               (byte)(value >> BYTE_SIZE_IN_BITS * 7)
             };
    }
    else {
      return new byte[] {
               (byte)(value >> BYTE_SIZE_IN_BITS * 7),
               (byte)(value >> BYTE_SIZE_IN_BITS * 6),
               (byte)(value >> BYTE_SIZE_IN_BITS * 5),
               (byte)(value >> BYTE_SIZE_IN_BITS * 4),
               (byte)(value >> BYTE_SIZE_IN_BITS * 3),
               (byte)(value >> BYTE_SIZE_IN_BITS * 2),
               (byte)(value >> BYTE_SIZE_IN_BITS * 1),
               (byte)(value                         )
             };
    }
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(long value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(long value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return a new MacAddress object.
   */
  public static MacAddress getMacAddress(byte[] array, int offset) {
    return getMacAddress(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new MacAddress object.
   */
  public static MacAddress getMacAddress(
    byte[] array, int offset, ByteOrder bo
  ) {
    validateBounds(array, offset, MacAddress.SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return MacAddress.getByAddress(
               reverse(getSubArray(array, offset, MacAddress.SIZE_IN_BYTES))
             );
    }
    else {
      return MacAddress.getByAddress(
               getSubArray(array, offset, MacAddress.SIZE_IN_BYTES)
             );
    }
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(MacAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(MacAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    }
    else {
      return value.getAddress();
    }
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param length length
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getLinkLayerAddress(byte[] array, int offset, int length) {
    return getLinkLayerAddress(array, offset, length, ByteOrder.BIG_ENDIAN);
  }


  /**
   *
   * @param array array
   * @param offset offset
   * @param length length
   * @param bo bo
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getLinkLayerAddress(
    byte[] array, int offset, int length, ByteOrder bo
  ) {
    validateBounds(array, offset, length);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return LinkLayerAddress.getByAddress(
               reverse(getSubArray(array, offset, length))
             );
    }
    else {
      return LinkLayerAddress.getByAddress(
               getSubArray(array, offset, length)
             );
    }
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(LinkLayerAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(LinkLayerAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    }
    else {
      return value.getAddress();
    }
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return a new Inet4Address object.
   */
  public static Inet4Address getInet4Address(byte[] array, int offset) {
    return getInet4Address(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new Inet4Address object.
   */
  public static Inet4Address getInet4Address(
    byte[] array, int offset, ByteOrder bo
  ) {
    validateBounds(array, offset, INET4_ADDRESS_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    try {
      if (bo.equals(LITTLE_ENDIAN)) {
        return (Inet4Address)InetAddress.getByAddress(
                 reverse(
                   getSubArray(
                     array,
                     offset,
                     INET4_ADDRESS_SIZE_IN_BYTES
                   )
                 )
               );
      }
      else {
        return (Inet4Address)InetAddress.getByAddress(
                 getSubArray(
                   array,
                   offset,
                   INET4_ADDRESS_SIZE_IN_BYTES
                 )
               );
      }
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return a new Inet6Address object.
   */
  public static Inet6Address getInet6Address(byte[] array, int offset) {
    return getInet6Address(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new Inet6Address object.
   */
  public static Inet6Address getInet6Address(
    byte[] array, int offset, ByteOrder bo
  ) {
    validateBounds(array, offset, INET6_ADDRESS_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    try {
      if (bo.equals(LITTLE_ENDIAN)) {
        return (Inet6Address)InetAddress.getByAddress(
                 reverse(
                   getSubArray(
                     array,
                     offset,
                     INET6_ADDRESS_SIZE_IN_BYTES
                   )
                 )
               );
      }
      else {
        return (Inet6Address)InetAddress.getByAddress(
                 getSubArray(
                   array,
                   offset,
                   INET6_ADDRESS_SIZE_IN_BYTES
                 )
               );
      }
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  /**
   *
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(InetAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   *
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(InetAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    }
    else {
      return value.getAddress();
    }
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @param length length
   * @return sub array
   */
  public static byte[] getSubArray(byte[] array, int offset, int length) {
    validateBounds(array, offset, length);

    byte[] subArray = new byte[length];
    System.arraycopy(array, offset, subArray, 0, length);
    return subArray;
  }

  /**
   *
   * @param array array
   * @param offset offset
   * @return sub array
   */
  public static byte[] getSubArray(byte[] array, int offset) {
    return getSubArray(array, offset, array.length - offset);
  }

  /**
   *
   * @param array array
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(byte[] array, String separator) {
    return toHexString(array, separator, 0, array.length);
  }

  /**
   *
   * @param array array
   * @param separator separator
   * @param offset offset
   * @param length length
   * @return hex string
   */
  public static String toHexString(
    byte[] array, String separator, int offset, int length
  ) {
    validateBounds(array, offset, length);

    char[] hexChars;
    if (separator.length() != 0) {
      char[] sepChars = separator.toCharArray();
      hexChars = new char[length * 2 + sepChars.length * (length - 1)];
      int cur = 0;
      int i = 0;
      for (; i < length - 1; i++) {
        int v = array[offset + i] & 0xFF;
        hexChars[cur] = HEX_CHARS[v >>> 4];
        cur++;
        hexChars[cur] = HEX_CHARS[v & 0x0F];
        cur++;
        for (int j = 0; j < sepChars.length; j++) {
          hexChars[cur] = sepChars[j];
          cur++;
        }
      }
      int v = array[offset + i] & 0xFF;
      hexChars[cur] = HEX_CHARS[v >>> 4];
      hexChars[cur + 1] = HEX_CHARS[v & 0x0F];
    }
    else {
      hexChars = new char[length * 2];
      int cur = 0;
      for (int i = 0; i < length; i++) {
        int v = array[offset + i] & 0xFF;
        hexChars[cur] = HEX_CHARS[v >>> 4];
        cur++;
        hexChars[cur] = HEX_CHARS[v & 0x0F];
        cur++;
      }
    }

    return new String(hexChars);
  }

  /**
   * A utility method to calculate the Internet checksum.
   *
   * @see <a href="https://tools.ietf.org/html/rfc1071">RFC 1071</a>
   * @param data data
   * @return checksum
   */
  public static short calcChecksum(byte[] data) {
    long sum = 0;
    for (int i = 1; i < data.length; i += SHORT_SIZE_IN_BYTES) {
        sum += 0xFFFFL & getShort(data, i - 1);
    }
    if (data.length % 2 != 0) {
      sum += 0xFFFFL & (data[data.length - 1] << BYTE_SIZE_IN_BITS) ;
    }

    while ((sum >> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES)) != 0) {
      sum = (0xFFFFL & sum) + (sum >>> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES));
    }

    return (short)~sum;
  }

  /**
   *
   * @param hexString hexString
   * @param separator separator
   * @return a new byte array.
   */
  public static byte[] parseByteArray(String hexString, String separator) {
    if (
         hexString == null
      || separator == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("hexString: ")
        .append(hexString)
        .append(" separator: ")
        .append(separator);
      throw new NullPointerException(sb.toString());
    }

    if (hexString.startsWith("0x")) {
      hexString = hexString.substring(2);
    }

    String noSeparatorHexString;
    if (separator.length() == 0) {
      if (
       !NO_SEPARATOR_HEX_STRING_PATTERN.matcher(hexString).matches()
      ) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("invalid hex string(")
          .append(hexString)
          .append("), not match pattern(")
          .append(NO_SEPARATOR_HEX_STRING_PATTERN.pattern())
          .append(")");
        throw new IllegalArgumentException(sb.toString());
      }
      noSeparatorHexString = hexString;
    }
    else {
      StringBuilder patternSb = new StringBuilder(60);
      patternSb.append("\\A[0-9a-fA-F][0-9a-fA-F](")
               .append(Pattern.quote(separator))
               .append("[0-9a-fA-F][0-9a-fA-F])*\\z");
      String patternString = patternSb.toString();

      Pattern pattern = Pattern.compile(patternString);
      if (!pattern.matcher(hexString).matches()) {
        StringBuilder sb = new StringBuilder(150);
        sb.append("invalid hex string(")
          .append(hexString)
          .append("), not match pattern(")
          .append(patternString)
          .append(")");
        throw new IllegalArgumentException(sb.toString());
      }
      noSeparatorHexString
        = hexString.replaceAll(Pattern.quote(separator), "");
    }

    int arrayLength = noSeparatorHexString.length() / 2;
    byte[] array = new byte[arrayLength];
    for (int i = 0; i < arrayLength; i++) {
      array[i]
        = (byte)Integer.parseInt(
            noSeparatorHexString.substring(i * 2, i * 2 + 2),
            16
          );
    }

    return array;
  }

  /**
   *
   * @param array array
   * @return a clone of array
   */
  public static byte[] clone(byte[] array) {
    byte[] clone = new byte[array.length];
    System.arraycopy(array, 0, clone, 0, array.length);
    return clone;
  }


  /**
   *
   * A utility method to validate arguments which indicate a part of an array.
   *
   * @param arr arr
   * @param offset offset
   * @param len len
   * @throws NullPointerException if the {@code arr} is null.
   * @throws IllegalArgumentException if {@code arr} is empty or {@code len} is zero.
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative,
   *         or ({@code offset} + {@code len}) is greater than or equal to {@code arr.length}.
   */
  public static void validateBounds(byte[] arr, int offset, int len) {
    if (arr == null) {
      throw new NullPointerException("arr must not be null.");
    }
    if (arr.length == 0) {
      throw new IllegalArgumentException("arr is empty.");
    }
    if (len == 0) {
      throw new IllegalArgumentException("length is zero.");
    }
    if (offset < 0 || len < 0 || offset + len > arr.length) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("arr.length: ")
        .append(arr.length)
        .append(", offset: ")
        .append(offset)
        .append(", len: ")
        .append(len);
      throw new ArrayIndexOutOfBoundsException(sb.toString());
    }
  }

  /**
   * @param arr1 arr1
   * @param arr2 arr2
   * @return arr1 xor arr2
   */
  public static byte[] xor(byte[] arr1, byte[] arr2) {
    if (arr1 == null) {
      throw new NullPointerException("arr1 must not be null.");
    }
    if (arr2 == null) {
      throw new NullPointerException("arr2 must not be null.");
    }
    if (arr1.length != arr2.length) {
      throw new IllegalArgumentException("arr1.length must equal to arr2.length.");
    }

    byte[] result = new byte[arr1.length];
    for (int i = 0; i < arr1.length; i++) {
      result[i] = (byte)(arr1[i] ^ arr2[i]);
    }

    return result;
  }

  /**
   * @param arr1 arr1
   * @param arr2 arr2
   * @return arr1 + arr2
   */
  public static byte[] concatenate(byte[] arr1, byte[] arr2) {
    byte[] result = new byte[arr1.length + arr2.length];
    System.arraycopy(arr1, 0, result, 0, arr1.length);
    System.arraycopy(arr2, 0, result, arr1.length, arr2.length);
    return result;
  }

}
