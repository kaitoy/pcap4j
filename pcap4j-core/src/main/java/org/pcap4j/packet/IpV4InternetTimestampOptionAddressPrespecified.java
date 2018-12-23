/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.net.Inet4Address;
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
public final class IpV4InternetTimestampOptionAddressPrespecified
    implements IpV4InternetTimestampOptionData {

  /*   0                            15                              31
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                      internet address                         |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           timestamp                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           timestamp                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                                .                              |
   *                                   .
   *                                   .
   */

  /** */
  private static final long serialVersionUID = 3865517048348635723L;

  private final Inet4Address address;
  private final List<Integer> timestamps;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4InternetTimestampOptionAddressPrespecified object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4InternetTimestampOptionAddressPrespecified newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4InternetTimestampOptionAddressPrespecified(rawData, offset, length);
  }

  private IpV4InternetTimestampOptionAddressPrespecified(byte[] rawData, int offset, int length)
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

    this.address = ByteArrays.getInet4Address(rawData, 0 + offset);

    this.timestamps = new ArrayList<Integer>();
    for (int i = INT_SIZE_IN_BYTES; i < length; i += INT_SIZE_IN_BYTES) {
      timestamps.add(ByteArrays.getInt(rawData, i + offset));
    }
  }

  /**
   * @param address address
   * @param timestamps timestamps
   */
  public IpV4InternetTimestampOptionAddressPrespecified(
      Inet4Address address, List<Integer> timestamps) {
    if (timestamps == null) {
      throw new NullPointerException("timestamps may not be null");
    }
    if (address == null && !timestamps.isEmpty()) {
      throw new IllegalArgumentException("timestamps.size() must be 0 if address is null");
    }

    this.address = address;
    this.timestamps = new ArrayList<Integer>(timestamps);
  }

  /** @return address */
  public Inet4Address getAddress() {
    return address;
  }

  /** @return timestamps */
  public List<Integer> getTimestamps() {
    return new ArrayList<Integer>(timestamps);
  }

  public int length() {
    if (address == null) {
      return 0;
    } else {
      return INET4_ADDRESS_SIZE_IN_BYTES + timestamps.size() * INT_SIZE_IN_BYTES;
    }
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
    if (address == null) {
      return "[]";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("[address: ").append(address);
    sb.append("] [timestamps:");
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
