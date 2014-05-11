/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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
public final class IllegalIpV4InternetTimestampOptionData implements IpV4InternetTimestampOptionData {

  /**
   *
   */
  private static final long serialVersionUID = 2799097946096468081L;

  private final byte[] rawData;

  /**
   *
   * @param rawData
   * @return a new IllegalIpV4InternetTimestampOptionData object.
   */
  public static IllegalIpV4InternetTimestampOptionData newInstance(byte[] rawData) {
    return new IllegalIpV4InternetTimestampOptionData(rawData);
  }

  private IllegalIpV4InternetTimestampOptionData(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
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
    sb.append("[illegal data: ")
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
