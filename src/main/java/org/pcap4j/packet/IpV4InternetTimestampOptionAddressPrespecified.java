/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;

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

  /**
   *
   */
  private static final long serialVersionUID = 3865517048348635723L;

  private final Inet4Address address;
  private final List<Integer> timestamps;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV4InternetTimestampOptionAddressPrespecified newInstance(
    byte[] rawData
  ) {
    return new IpV4InternetTimestampOptionAddressPrespecified(rawData);
  }

  private IpV4InternetTimestampOptionAddressPrespecified(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if ((rawData.length % INT_SIZE_IN_BYTES) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append(
          "The raw data length must be an integer multiple of 4 octets long."
            + " rawData: "
        )
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    if (rawData.length != 0) {
      this.address = ByteArrays.getInet4Address(rawData, 0);
    }
    else {
      this.address = null;
    }

    this.timestamps = new ArrayList<Integer>();
    for (int i = INT_SIZE_IN_BYTES; i < rawData.length; i += INT_SIZE_IN_BYTES) {
      timestamps.add(ByteArrays.getInt(rawData, i));
    }
  }

  /**
   *
   * @param address
   * @param timestamps
   */
  public IpV4InternetTimestampOptionAddressPrespecified(
    Inet4Address address, List<Integer> timestamps
  ) {
    if (timestamps == null) {
      throw new NullPointerException("timestamps may not be null");
    }
    if (address == null && timestamps.size() != 0) {
      throw new IllegalArgumentException(
              "timestamps.size() must be 0 if address is null"
            );
    }

    this.address = address;
    this.timestamps = new ArrayList<Integer>(timestamps);
  }

  /**
   *
   * @return
   */
  public Inet4Address getAddress() { return address; }

  /**
   *
   * @return
   */
  public List<Integer> getTimestamps() {
    return new ArrayList<Integer>(timestamps);
  }

  public int length() {
    if (address == null) {
      return 0;
    }
    else {
      return INET4_ADDRESS_SIZE_IN_BYTES
               + timestamps.size() * INT_SIZE_IN_BYTES;
    }
  }

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
    if (address == null) { return "[]"; }

    StringBuilder sb = new StringBuilder();
    sb.append("[address: ")
      .append(address);
    sb.append("] [timestamps:");
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
