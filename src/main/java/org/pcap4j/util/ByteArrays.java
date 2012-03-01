/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.util.MacAddress;

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
  public static final int IP_ADDRESS_SIZE_IN_BYTES = 4;

  /**
   *
   */
  public static final int BYTE_SIZE_IN_BITS = 8;

  private ByteArrays() { throw new AssertionError(); }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static byte getByte(byte[] array, int offset) {
    if (offset + BYTE_SIZE_IN_BYTES > array.length) {
      throw new IllegalArgumentException();
    }
    return array[offset];
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(byte value) {
    return new byte[] { value };
  }

  /**
   *
   * @param value
   * @param separator
   * @return
   */
  public static String toHexString(byte value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static short getShort(byte[] array, int offset) {
    if (offset + SHORT_SIZE_IN_BYTES > array.length) {
      throw new IllegalArgumentException();
    }
    return (short)(
                ((0xFF & array[offset    ]) << (BYTE_SIZE_IN_BITS * 1))
              | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 0))
            );
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(short value) {
    return new byte[] {
             (byte)((value & 0xFF00) >> BYTE_SIZE_IN_BITS * 1),
             (byte)((value & 0x00FF) >> BYTE_SIZE_IN_BITS * 0)
           };
  }

  /**
   *
   * @param value
   * @param separator
   * @return
   */
  public static String toHexString(short value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static int getInt(byte[] array, int offset) {
    if (offset + INT_SIZE_IN_BYTES > array.length) {
      throw new IllegalArgumentException();
    }
    return (int)(
                ((0xFF & array[offset    ]) << (BYTE_SIZE_IN_BITS * 3))
              | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 2))
              | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 1))
              | ((0xFF & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 0))
            );
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(int value) {
    return new byte[] {
             (byte)((value & 0xFF000000) >> BYTE_SIZE_IN_BITS * 3),
             (byte)((value & 0x00FF0000) >> BYTE_SIZE_IN_BITS * 2),
             (byte)((value & 0x0000FF00) >> BYTE_SIZE_IN_BITS * 1),
             (byte)((value & 0x000000FF) >> BYTE_SIZE_IN_BITS * 0)
           };
  }

  /**
   *
   * @param value
   * @param separator
   * @return
   */
  public static String toHexString(int value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static long getLong(byte[] array, int offset) {
    if (offset + LONG_SIZE_IN_BYTES > array.length) {
      throw new IllegalArgumentException();
    }
    return (long)(
                ((0xFF & array[offset    ]) << (BYTE_SIZE_IN_BITS * 7))
              | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 6))
              | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 5))
              | ((0xFF & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 4))
              | ((0xFF & array[offset + 4]) << (BYTE_SIZE_IN_BITS * 3))
              | ((0xFF & array[offset + 5]) << (BYTE_SIZE_IN_BITS * 2))
              | ((0xFF & array[offset + 6]) << (BYTE_SIZE_IN_BITS * 1))
              | ((0xFF & array[offset + 7]) << (BYTE_SIZE_IN_BITS * 0))
            );
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(long value) {
    return new byte[] {
             (byte)((value & 0xFF00000000000000L) >> BYTE_SIZE_IN_BITS * 7),
             (byte)((value & 0x00FF000000000000L) >> BYTE_SIZE_IN_BITS * 6),
             (byte)((value & 0x0000FF0000000000L) >> BYTE_SIZE_IN_BITS * 5),
             (byte)((value & 0x000000FF00000000L) >> BYTE_SIZE_IN_BITS * 4),
             (byte)((value & 0x00000000FF000000L) >> BYTE_SIZE_IN_BITS * 3),
             (byte)((value & 0x0000000000FF0000L) >> BYTE_SIZE_IN_BITS * 2),
             (byte)((value & 0x000000000000FF00L) >> BYTE_SIZE_IN_BITS * 1),
             (byte)((value & 0x00000000000000FFL) >> BYTE_SIZE_IN_BITS * 0)
           };
  }

  /**
   *
   * @param value
   * @param separator
   * @return
   */
  public static String toHexString(long value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static MacAddress getMacAddress(byte[] array, int offset) {
    return MacAddress.newInstance(
             getSubArray(array, offset, MacAddress.SIZE_IN_BYTES)
           );
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(MacAddress value) {
    return value.getAddress();
  }

  /**
   *
   * @param array
   * @param offset
   * @return
   */
  public static Inet4Address getInet4Address(byte[] array, int offset) {
    try {
      return (Inet4Address)Inet4Address.getByAddress(
                             getSubArray(
                               array,
                               offset,
                               IP_ADDRESS_SIZE_IN_BYTES
                             )
                           );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
  }

  /**
   *
   * @param value
   * @return
   */
  public static byte[] toByteArray(InetAddress value) {
    return value.getAddress();
  }

  /**
   *
   * @param array
   * @param offset
   * @param size
   * @return
   */
  public static byte[] getSubArray(byte[] array, int offset, int size) {
    byte[] subArray = new byte[size];
    System.arraycopy(array, offset, subArray, 0, size);
    return subArray;
  }

  /**
   *
   * @param array
   * @param separator
   * @return
   */
  public static String toHexString(byte[] array, String separator) {
    StringBuffer buf = new StringBuffer();

    for (int i = 0; i < array.length; i++) {
      buf.append(String.format("%02x", array[i]));
      buf.append(separator);
    }

    if (separator.length() != 0 && array.length > 0) {
      buf.delete(buf.lastIndexOf(separator), buf.length());
    }

    return buf.toString();
  }

  /**
   *
   * @param data
   * @return
   */
  public static short calcChecksum(byte[] data) {
    int sum = 0;
    for (int i = 0; i < data.length; i += SHORT_SIZE_IN_BYTES) {
      sum += (0xFFFF) & ByteArrays.getShort(data, i);
    }

    sum
      = (0xFFFF & sum)
        + ((0xFFFF0000 & sum) >> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES));
    sum
      = (0xFFFF & sum)
        + ((0xFFFF0000 & sum) >> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES));

    return (short)(0xFFFF & ~sum);
  }

}
