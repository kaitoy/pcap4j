/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class UnknownIpV4InternetTimestampData implements IpV4InternetTimestampOptionData {

  /**
   *
   */
  private static final long serialVersionUID = 2799097946096468081L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new UnknownIpV4InternetTimestampData object.
   */
  public static UnknownIpV4InternetTimestampData newInstance(byte[] rawData) {
    return new UnknownIpV4InternetTimestampData(rawData);
  }

  private UnknownIpV4InternetTimestampData(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
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
