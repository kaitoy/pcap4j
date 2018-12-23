/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4InternetTimestampOptionTimestamps
    implements IpV4InternetTimestampOptionData {

  /*   0                            15                              31
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           timestamp                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                                .                              |
   *                                   .
   *                                   .
   */

  /** */
  private static final long serialVersionUID = -2067863811913941432L;

  private final List<Integer> timestamps;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4InternetTimestampOptionTimestamps object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4InternetTimestampOptionTimestamps newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4InternetTimestampOptionTimestamps(rawData, offset, length);
  }

  private IpV4InternetTimestampOptionTimestamps(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if ((length % INT_SIZE_IN_BYTES) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be an integer multiple of 4 octets long." + " rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.timestamps = new ArrayList<Integer>();
    for (int i = 0; i < length; i += INT_SIZE_IN_BYTES) {
      timestamps.add(ByteArrays.getInt(rawData, i + offset));
    }
  }

  /** @param timestamps timestamps */
  public IpV4InternetTimestampOptionTimestamps(List<Integer> timestamps) {
    if (timestamps == null) {
      throw new NullPointerException("timestamps may not be null");
    }
    this.timestamps = new ArrayList<Integer>(timestamps);
  }

  /** @return timestamps */
  public List<Integer> getTimestamps() {
    return new ArrayList<Integer>(timestamps);
  }

  public int length() {
    return timestamps.size() * INT_SIZE_IN_BYTES;
  }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    Iterator<Integer> iter = timestamps.iterator();
    for (int i = 0; i < rawData.length; i += INT_SIZE_IN_BYTES) {
      System.arraycopy(ByteArrays.toByteArray(iter.next()), 0, rawData, 0, INT_SIZE_IN_BYTES);
    }
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[timestamps:");
    for (Integer ts : timestamps) {
      sb.append(" ").append(ts & 0xFFFFFFFFL);
    }
    sb.append("]");
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
    return Arrays.equals((getClass().cast(obj)).getRawData(), getRawData());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }
}
