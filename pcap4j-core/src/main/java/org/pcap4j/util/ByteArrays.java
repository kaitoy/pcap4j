/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019  Pcap4J.org
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
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.Adler32;
import java.util.zip.CRC32;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ByteArrays {

  /** */
  public static final int BYTE_SIZE_IN_BYTES = 1;

  /** */
  public static final int SHORT_SIZE_IN_BYTES = 2;

  /** */
  public static final int INT_SIZE_IN_BYTES = 4;

  /** */
  public static final int LONG_SIZE_IN_BYTES = 8;

  /** */
  public static final int INET4_ADDRESS_SIZE_IN_BYTES = 4;

  /** */
  public static final int INET6_ADDRESS_SIZE_IN_BYTES = 16;

  /** */
  public static final int BYTE_SIZE_IN_BITS = 8;

  private static final Pattern NO_SEPARATOR_HEX_STRING_PATTERN =
      Pattern.compile("\\A([0-9a-fA-F][0-9a-fA-F])+\\z");

  private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

  private static final int[] CRC32C_TABLE =
      new int[] {
        0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8,
            0xd4ca64eb,
        0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27,
            0x5e133c24,
        0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087,
            0xc494a384,
        0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848,
            0x4e4dfb4b,
        0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936,
            0xf477ea35,
        0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9,
            0x7eaeb2fa,
        0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59,
            0xe4292d5a,
        0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696,
            0x6ef07595,
        0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54,
            0x95b17957,
        0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b,
            0x1f682198,
        0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b,
            0x85efbe38,
        0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4,
            0x0f36e6f7,
        0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a,
            0xb50cf789,
        0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45,
            0x3fd5af46,
        0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5,
            0xa55230e6,
        0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a,
            0x2f8b6829,
        0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90,
            0x563c5f93,
        0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f,
            0xdce5075c,
        0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff,
            0x466298fc,
        0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330,
            0xccbbc033,
        0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e,
            0x7681d14d,
        0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81,
            0xfc588982,
        0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521,
            0x66df1622,
        0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee,
            0xec064eed,
        0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c,
            0x1747422f,
        0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3,
            0x9d9e1ae0,
        0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643,
            0x07198540,
        0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c,
            0x8dc0dd8f,
        0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2,
            0x37faccf1,
        0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d,
            0xbd23943e,
        0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d,
            0x27a40b9e,
        0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052,
            0xad7d5351,
      };

  private ByteArrays() {
    throw new AssertionError();
  }

  /**
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
   * @param array array
   * @param offset offset
   * @return byte value.
   */
  public static byte getByte(byte[] array, int offset) {
    validateBounds(array, offset, BYTE_SIZE_IN_BYTES);
    return array[offset];
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(byte value) {
    return new byte[] {value};
  }

  /**
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(byte value, String separator) {
    return toHexString(toByteArray(value), separator);
  }

  /**
   * @param array array
   * @param offset offset
   * @return short value
   */
  public static short getShort(byte[] array, int offset) {
    return getShort(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
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
      return (short) (((array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1)) | ((0xFF & array[offset])));
    } else {
      return (short) (((array[offset]) << (BYTE_SIZE_IN_BITS * 1)) | ((0xFF & array[offset + 1])));
    }
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(short value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(short value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {(byte) (value), (byte) (value >> BYTE_SIZE_IN_BITS * 1)};
    } else {
      return new byte[] {(byte) (value >> BYTE_SIZE_IN_BITS * 1), (byte) (value)};
    }
  }

  /**
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(short value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(short value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   * @param array array
   * @param offset offset
   * @return int value.
   */
  public static int getInt(byte[] array, int offset) {
    return getInt(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
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
      return ((array[offset + 3]) << (BYTE_SIZE_IN_BITS * 3))
          | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 2))
          | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1))
          | ((0xFF & array[offset]));
    } else {
      return ((array[offset]) << (BYTE_SIZE_IN_BITS * 3))
          | ((0xFF & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 2))
          | ((0xFF & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 1))
          | ((0xFF & array[offset + 3]));
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
      StringBuilder sb =
          new StringBuilder(30)
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
    } else {
      for (int i = offset; i < offset + length; i++) {
        value <<= BYTE_SIZE_IN_BITS;
        value |= 0xFF & array[i];
      }
    }
    return value;
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(int value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(int value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {
        (byte) (value),
        (byte) (value >> BYTE_SIZE_IN_BITS * 1),
        (byte) (value >> BYTE_SIZE_IN_BITS * 2),
        (byte) (value >> BYTE_SIZE_IN_BITS * 3),
      };
    } else {
      return new byte[] {
        (byte) (value >> BYTE_SIZE_IN_BITS * 3),
        (byte) (value >> BYTE_SIZE_IN_BITS * 2),
        (byte) (value >> BYTE_SIZE_IN_BITS * 1),
        (byte) (value)
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
      StringBuilder sb =
          new StringBuilder(30)
              .append("length must be equal or less than ")
              .append(INT_SIZE_IN_BYTES)
              .append(", but is: ")
              .append(length);
      throw new IllegalArgumentException(sb.toString());
    }

    byte[] arr = new byte[length];
    if (bo.equals(LITTLE_ENDIAN)) {
      for (int i = 0; i < length; i++) {
        arr[length - i - 1] = (byte) (value >> BYTE_SIZE_IN_BITS * i);
      }
    } else {
      for (int i = 0; i < length; i++) {
        arr[i] = (byte) (value >> BYTE_SIZE_IN_BITS * i);
      }
    }

    return arr;
  }

  /**
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(int value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(int value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   * @param array array
   * @param offset offset
   * @return long value
   */
  public static long getLong(byte[] array, int offset) {
    return getLong(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
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
      return (((long) array[offset + 7]) << (BYTE_SIZE_IN_BITS * 7))
          | ((0xFFL & array[offset + 6]) << (BYTE_SIZE_IN_BITS * 6))
          | ((0xFFL & array[offset + 5]) << (BYTE_SIZE_IN_BITS * 5))
          | ((0xFFL & array[offset + 4]) << (BYTE_SIZE_IN_BITS * 4))
          | ((0xFFL & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 3))
          | ((0xFFL & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 2))
          | ((0xFFL & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 1))
          | ((0xFFL & array[offset]));
    } else {
      return (((long) array[offset]) << (BYTE_SIZE_IN_BITS * 7))
          | ((0xFFL & array[offset + 1]) << (BYTE_SIZE_IN_BITS * 6))
          | ((0xFFL & array[offset + 2]) << (BYTE_SIZE_IN_BITS * 5))
          | ((0xFFL & array[offset + 3]) << (BYTE_SIZE_IN_BITS * 4))
          | ((0xFFL & array[offset + 4]) << (BYTE_SIZE_IN_BITS * 3))
          | ((0xFFL & array[offset + 5]) << (BYTE_SIZE_IN_BITS * 2))
          | ((0xFFL & array[offset + 6]) << (BYTE_SIZE_IN_BITS * 1))
          | ((0xFFL & array[offset + 7]));
    }
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(long value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(long value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return new byte[] {
        (byte) (value),
        (byte) (value >> BYTE_SIZE_IN_BITS * 1),
        (byte) (value >> BYTE_SIZE_IN_BITS * 2),
        (byte) (value >> BYTE_SIZE_IN_BITS * 3),
        (byte) (value >> BYTE_SIZE_IN_BITS * 4),
        (byte) (value >> BYTE_SIZE_IN_BITS * 5),
        (byte) (value >> BYTE_SIZE_IN_BITS * 6),
        (byte) (value >> BYTE_SIZE_IN_BITS * 7)
      };
    } else {
      return new byte[] {
        (byte) (value >> BYTE_SIZE_IN_BITS * 7),
        (byte) (value >> BYTE_SIZE_IN_BITS * 6),
        (byte) (value >> BYTE_SIZE_IN_BITS * 5),
        (byte) (value >> BYTE_SIZE_IN_BITS * 4),
        (byte) (value >> BYTE_SIZE_IN_BITS * 3),
        (byte) (value >> BYTE_SIZE_IN_BITS * 2),
        (byte) (value >> BYTE_SIZE_IN_BITS * 1),
        (byte) (value)
      };
    }
  }

  /**
   * @param value value
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(long value, String separator) {
    return toHexString(value, separator, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param separator separator
   * @param bo bo
   * @return hex string
   */
  public static String toHexString(long value, String separator, ByteOrder bo) {
    return toHexString(toByteArray(value, bo), separator);
  }

  /**
   * @param array array
   * @param offset offset
   * @return a new MacAddress object.
   */
  public static MacAddress getMacAddress(byte[] array, int offset) {
    return getMacAddress(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new MacAddress object.
   */
  public static MacAddress getMacAddress(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, MacAddress.SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return MacAddress.getByAddress(reverse(getSubArray(array, offset, MacAddress.SIZE_IN_BYTES)));
    } else {
      return MacAddress.getByAddress(getSubArray(array, offset, MacAddress.SIZE_IN_BYTES));
    }
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(MacAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(MacAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    } else {
      return value.getAddress();
    }
  }

  /**
   * @param array array
   * @param offset offset
   * @param length length
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getLinkLayerAddress(byte[] array, int offset, int length) {
    return getLinkLayerAddress(array, offset, length, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param array array
   * @param offset offset
   * @param length length
   * @param bo bo
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getLinkLayerAddress(
      byte[] array, int offset, int length, ByteOrder bo) {
    validateBounds(array, offset, length);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    if (bo.equals(LITTLE_ENDIAN)) {
      return LinkLayerAddress.getByAddress(reverse(getSubArray(array, offset, length)));
    } else {
      return LinkLayerAddress.getByAddress(getSubArray(array, offset, length));
    }
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(LinkLayerAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(LinkLayerAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    } else {
      return value.getAddress();
    }
  }

  /**
   * @param array array
   * @param offset offset
   * @return a new Inet4Address object.
   */
  public static Inet4Address getInet4Address(byte[] array, int offset) {
    return getInet4Address(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new Inet4Address object.
   */
  public static Inet4Address getInet4Address(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, INET4_ADDRESS_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    try {
      if (bo.equals(LITTLE_ENDIAN)) {
        return (Inet4Address)
            InetAddress.getByAddress(
                reverse(getSubArray(array, offset, INET4_ADDRESS_SIZE_IN_BYTES)));
      } else {
        return (Inet4Address)
            InetAddress.getByAddress(getSubArray(array, offset, INET4_ADDRESS_SIZE_IN_BYTES));
      }
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @param addr a string representation of an IPv4 address. (e.g. "192.168.0.100")
   * @return a byte array representation of the IPv4 address.
   * @throws IllegalArgumentException if failed to parse addr.
   */
  public static byte[] parseInet4Address(String addr) {
    String[] octetStrs = addr.split("\\.", 4);
    if (octetStrs.length != INET4_ADDRESS_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("Couldn't get an Inet4Address from " + addr);
    }

    byte[] octets = new byte[4];
    for (int i = 0; i < octets.length; i++) {
      String octetStr = octetStrs[i];
      try {
        int octet = Integer.parseInt(octetStr);
        if (octet < 0 || octet > 255) {
          throw new IllegalArgumentException("Couldn't get an Inet4Address from " + addr);
        }
        octets[i] = (byte) octet;
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Couldn't get an Inet4Address from " + addr);
      }
    }

    return octets;
  }

  /**
   * @param array array
   * @param offset offset
   * @return a new Inet6Address object.
   */
  public static Inet6Address getInet6Address(byte[] array, int offset) {
    return getInet6Address(array, offset, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param array array
   * @param offset offset
   * @param bo bo
   * @return a new Inet6Address object.
   */
  public static Inet6Address getInet6Address(byte[] array, int offset, ByteOrder bo) {
    validateBounds(array, offset, INET6_ADDRESS_SIZE_IN_BYTES);

    if (bo == null) {
      throw new NullPointerException(" bo: " + bo);
    }

    try {
      if (bo.equals(LITTLE_ENDIAN)) {
        return Inet6Address.getByAddress(
            null, reverse(getSubArray(array, offset, INET6_ADDRESS_SIZE_IN_BYTES)), -1);
      } else {
        return Inet6Address.getByAddress(
            null, getSubArray(array, offset, INET6_ADDRESS_SIZE_IN_BYTES), -1);
      }
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @param value value
   * @return byte array
   */
  public static byte[] toByteArray(InetAddress value) {
    return toByteArray(value, ByteOrder.BIG_ENDIAN);
  }

  /**
   * @param value value
   * @param bo bo
   * @return byte array
   */
  public static byte[] toByteArray(InetAddress value, ByteOrder bo) {
    if (bo.equals(LITTLE_ENDIAN)) {
      return reverse(value.getAddress());
    } else {
      return value.getAddress();
    }
  }

  /**
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
   * @param array array
   * @param offset offset
   * @return sub array
   */
  public static byte[] getSubArray(byte[] array, int offset) {
    return getSubArray(array, offset, array.length - offset);
  }

  /**
   * @param array array
   * @param separator separator
   * @return hex string
   */
  public static String toHexString(byte[] array, String separator) {
    return toHexString(array, separator, 0, array.length);
  }

  /**
   * @param array array
   * @param separator separator
   * @param offset offset
   * @param length length
   * @return hex string
   */
  public static String toHexString(byte[] array, String separator, int offset, int length) {
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
    } else {
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
      sum += 0xFFFFL & (data[data.length - 1] << BYTE_SIZE_IN_BITS);
    }

    while ((sum >> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES)) != 0) {
      sum = (0xFFFFL & sum) + (sum >>> (BYTE_SIZE_IN_BITS * SHORT_SIZE_IN_BYTES));
    }

    return (short) ~sum;
  }

  /**
   * A utility method to calculate CRC-32 checksum.
   *
   * @param data data
   * @return checksum
   */
  public static int calcCrc32Checksum(byte[] data) {
    CRC32 crc32 = new CRC32();
    crc32.update(data);
    return (int) crc32.getValue();
  }

  /**
   * A utility method to calculate CRC-32C checksum.
   *
   * @param data data
   * @return checksum
   */
  public static int calcCrc32cChecksum(byte[] data) {
    int c = 0xFFFFFFFF;
    for (int i = 0; i < data.length; i++) {
      c = CRC32C_TABLE[(c ^ data[i]) & 0xFF] ^ (c >>> 8);
    }
    return c ^ 0xFFFFFFFF;
  }

  /**
   * A utility method to calculate Adler-32 checksum.
   *
   * @param data data
   * @return checksum
   */
  public static int calcAdler32Checksum(byte[] data) {
    Adler32 adler32 = new Adler32();
    adler32.update(data);
    return (int) adler32.getValue();
  }

  /**
   * @param hexString hexString
   * @param separator separator
   * @return a new byte array.
   */
  public static byte[] parseByteArray(String hexString, String separator) {
    if (hexString == null || separator == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("hexString: ").append(hexString).append(" separator: ").append(separator);
      throw new NullPointerException(sb.toString());
    }

    if (hexString.startsWith("0x")) {
      hexString = hexString.substring(2);
    }

    String noSeparatorHexString;
    if (separator.length() == 0) {
      if (!NO_SEPARATOR_HEX_STRING_PATTERN.matcher(hexString).matches()) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("invalid hex string(")
            .append(hexString)
            .append("), not match pattern(")
            .append(NO_SEPARATOR_HEX_STRING_PATTERN.pattern())
            .append(")");
        throw new IllegalArgumentException(sb.toString());
      }
      noSeparatorHexString = hexString;
    } else {
      StringBuilder patternSb = new StringBuilder(60);
      patternSb
          .append("\\A[0-9a-fA-F][0-9a-fA-F](")
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
      noSeparatorHexString = hexString.replaceAll(Pattern.quote(separator), "");
    }

    int arrayLength = noSeparatorHexString.length() / 2;
    byte[] array = new byte[arrayLength];
    for (int i = 0; i < arrayLength; i++) {
      array[i] = (byte) Integer.parseInt(noSeparatorHexString.substring(i * 2, i * 2 + 2), 16);
    }

    return array;
  }

  /**
   * @param array array
   * @return a clone of array
   */
  public static byte[] clone(byte[] array) {
    byte[] clone = new byte[array.length];
    System.arraycopy(array, 0, clone, 0, array.length);
    return clone;
  }

  /**
   * A utility method to validate arguments which indicate a part of an array.
   *
   * @param arr arr
   * @param offset offset
   * @param len len
   * @throws NullPointerException if the {@code arr} is null.
   * @throws IllegalArgumentException if {@code arr} is empty or {@code len} is zero.
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative, or ({@code
   *     offset} + {@code len}) is greater than or equal to {@code arr.length}.
   */
  public static void validateBounds(byte[] arr, int offset, int len) {
    if (arr == null) {
      throw new NullPointerException("arr must not be null.");
    }
    if (arr.length == 0) {
      throw new IllegalArgumentException("arr is empty.");
    }
    if (len == 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("length is zero. offset: ")
          .append(offset)
          .append(", arr: ")
          .append(toHexString(arr, ""));
      throw new IllegalArgumentException(sb.toString());
    }
    if (offset < 0 || len < 0 || offset + len > arr.length) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("arr.length: ")
          .append(arr.length)
          .append(", offset: ")
          .append(offset)
          .append(", len: ")
          .append(len)
          .append(", arr: ")
          .append(toHexString(arr, ""));
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
      result[i] = (byte) (arr1[i] ^ arr2[i]);
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

  /**
   * @param arrs arrays
   * @return the concatenated array.
   */
  public static byte[] concatenate(List<byte[]> arrs) {
    int length = 0;
    for (byte[] arr : arrs) {
      length += arr.length;
    }

    byte[] result = new byte[length];
    int destPos = 0;
    for (byte[] arr : arrs) {
      System.arraycopy(arr, 0, result, destPos, arr.length);
      destPos += arr.length;
    }

    return result;
  }
}
