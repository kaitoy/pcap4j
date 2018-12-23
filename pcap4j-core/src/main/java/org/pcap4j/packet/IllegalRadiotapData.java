/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class IllegalRadiotapData implements RadiotapData, IllegalRawDataHolder {

  /** */
  private static final long serialVersionUID = -707921517685565944L;

  private final byte[] rawData;
  private final IllegalRawDataException cause;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param cause cause
   * @return a new UnknownRadiotapDataField object.
   */
  public static IllegalRadiotapData newInstance(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    if (cause == null) {
      throw new NullPointerException("cause is null.");
    }
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalRadiotapData(rawData, offset, length, cause);
  }

  private IllegalRadiotapData(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    this.rawData = ByteArrays.getSubArray(rawData, offset, length);
    this.cause = cause;
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    return ByteArrays.clone(rawData);
  }

  @Override
  public IllegalRawDataException getCause() {
    return cause;
  }

  @Override
  public String toString() {
    return toString("");
  }

  @Override
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("Illegal Data: ")
        .append(ls)
        .append(indent)
        .append("  data: ")
        .append(ByteArrays.toHexString(rawData, ""))
        .append(ls)
        .append(indent)
        .append("  cause: ")
        .append(cause)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + cause.hashCode();
    result = prime * result + Arrays.hashCode(rawData);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    IllegalRadiotapData other = (IllegalRadiotapData) obj;
    if (!cause.equals(other.cause)) {
      return false;
    }
    if (!Arrays.equals(rawData, other.rawData)) {
      return false;
    }
    return true;
  }
}
