/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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

  /**
   *
   */
  private static final long serialVersionUID = -2067863811913941432L;

  private final List<Integer> timestamps;

  /**
   *
   * @param rawData
   * @return a new IpV4InternetTimestampOptionTimestamps object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IpV4InternetTimestampOptionTimestamps newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IpV4InternetTimestampOptionTimestamps(rawData);
  }

  private IpV4InternetTimestampOptionTimestamps(
    byte[] rawData
  ) throws IllegalRawDataException {
    if ((rawData.length % INT_SIZE_IN_BYTES) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append(
          "The raw data length must be an integer multiple of 4 octets long."
            + " rawData: "
        )
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.timestamps = new ArrayList<Integer>();
    for (int i = 0; i < rawData.length; i += INT_SIZE_IN_BYTES) {
      timestamps.add(ByteArrays.getInt(rawData, i));
    }
  }

  /**
   *
   * @param timestamps
   */
  public IpV4InternetTimestampOptionTimestamps(List<Integer> timestamps) {
    if (timestamps == null) {
      throw new NullPointerException("timestamps may not be null");
    }
    this.timestamps = new ArrayList<Integer>(timestamps);
  }

  /**
   *
   * @return timestamps
   */
  public List<Integer> getTimestamps() {
    return new ArrayList<Integer>(timestamps);
  }

  public int length() { return timestamps.size() * INT_SIZE_IN_BYTES; }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    Iterator<Integer> iter = timestamps.iterator();
    for (int i = 0; i < rawData.length; i += INT_SIZE_IN_BYTES) {
      System.arraycopy(
        ByteArrays.toByteArray(iter.next()), 0,
        rawData, 0, INT_SIZE_IN_BYTES
      );
    }
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[timestamps:");
    for (Integer ts: timestamps) {
      sb.append(" ")
        .append(ts & 0xFFFFFFFFL);
    }
    sb.append("]");
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
