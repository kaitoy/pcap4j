/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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

  /**
   *
   */
  private static final long serialVersionUID = -6359533865311266265L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new UnknownIpV6RoutingData object.
   * @throws IllegalRawDataException
   */
  public static UnknownIpV6RoutingData newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    return new UnknownIpV6RoutingData(rawData);
  }

  private UnknownIpV6RoutingData(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (((rawData.length + 4) % 8) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("(rawData.length + 8 ) % 8 must be 0. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.rawData = new byte[rawData.length];
    System.arraycopy(rawData, 0, this.rawData, 0, rawData.length);
  }

  public int length() { return rawData.length; }

  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, rawData.length);
    return copy;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[data: ")
      .append(ByteArrays.toHexString(rawData, ""))
      .append("]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    return Arrays.equals((getClass().cast(obj)).getRawData(), getRawData());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }

}
