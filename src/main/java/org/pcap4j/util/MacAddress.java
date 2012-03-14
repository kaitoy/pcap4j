/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.Serializable;
import java.util.Arrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class MacAddress implements Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 751211532491344621L;

  /**
   *
   */
  public static final MacAddress ETHER_BROADCAST_ADDRESS
    = MacAddress.getByAddress(
        new byte[]{
          (byte)255, (byte)255, (byte)255, (byte)255, (byte)255, (byte)255
        }
      );

  /**
   *
   */
  public static final int SIZE_IN_BYTES = 6;

  private final byte[] address;

  private MacAddress(byte[] address) { this.address = address; }

  /**
   *
   * @param address
   * @return
   */
  public static MacAddress getByAddress(byte[] address) {
    if (address.length != SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
              ByteArrays.toHexString(address, ":")
                + " is invalid for address. The length must be "
                + SIZE_IN_BYTES
            );
    }
    byte[] copy = new byte[address.length];
    System.arraycopy(address, 0, copy, 0, copy.length);
    return new MacAddress(copy);
  }

  /**
   *
   * @param name
   * @param separator
   * @return
   */
  public static MacAddress getByName(String name, String separator) {
    return getByAddress(ByteArrays.parseByteArray(name, separator));
  }

  /**
   *
   * @return
   */
  public byte[] getAddress() {
    byte[] copy = new byte[address.length];
    System.arraycopy(address, 0, copy, 0, copy.length);
    return copy;
  }

  /**
   *
   * @return
   */
  public byte[] getOui() {
    return new byte[] {address[0], address[1], address[2]};
  }

  /**
   *
   * @return
   */
  public boolean isUnicast() {
    return (address[0] & 1) == 0;
  }

  /**
   *
   * @return
   */
  public boolean isGloballyUnique() {
    return (address[0] & 2) == 0;
  }

  /**
   *
   * @return
   */
  public int length() {
    return address.length;
  }

  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();
    for (byte b: address) {
      sb.append(String.format("%02x", b))
        .append(":");
    }
    sb.deleteCharAt(sb.length() - 1);

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!(obj instanceof MacAddress)) { return false; }
    return Arrays.equals(((MacAddress)obj).getAddress(), address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }

}
