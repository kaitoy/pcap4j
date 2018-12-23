/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class UnknownIpV6RoutingData implements IpV6RoutingData {

  /** */
  private static final long serialVersionUID = -6359533865311266265L;

  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownIpV6RoutingData object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownIpV6RoutingData newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownIpV6RoutingData(rawData, offset, length);
  }

  private UnknownIpV6RoutingData(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (((length + 4) % 8) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("(length + 4) % 8 must be 0. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, rawData.length);
    return copy;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[data: ").append(ByteArrays.toHexString(rawData, " ")).append("]");
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

    UnknownIpV6RoutingData other = (UnknownIpV6RoutingData) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(rawData);
  }
}
