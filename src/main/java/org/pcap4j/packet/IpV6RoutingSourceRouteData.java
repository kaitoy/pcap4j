/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.INET6_ADDRESS_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV6RoutingSourceRouteData implements IpV6RoutingData {

  /**
   *
   */
  private static final long serialVersionUID = -7972526977248222954L;

  private final int reserved;
  private final List<Inet6Address> addresses;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV6RoutingSourceRouteData newInstance(byte[] rawData) {
    return new IpV6RoutingSourceRouteData(rawData);
  }

  private IpV6RoutingSourceRouteData(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (((rawData.length - 4) % INET6_ADDRESS_SIZE_IN_BYTES) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("(rawData.length -4 ) % ").append(INET6_ADDRESS_SIZE_IN_BYTES)
        .append(" must be 0. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.reserved = ByteArrays.getInt(rawData, 0);
    this.addresses = new ArrayList<Inet6Address>();

    for (
      int i = INT_SIZE_IN_BYTES;
      i < rawData.length;
      i += INET6_ADDRESS_SIZE_IN_BYTES
    ) {
      addresses.add(ByteArrays.getInet6Address(rawData, i));
    }
  }

  /**
   *
   * @param reserved
   * @param addresses
   */
  public IpV6RoutingSourceRouteData(int reserved, List<Inet6Address> addresses) {
    if (addresses == null) {
      throw new NullPointerException("addresses must not be null");
    }
    this.reserved = reserved;
    this.addresses = new ArrayList<Inet6Address>(addresses);
  }

  public int length() {
    return addresses.size() * INET6_ADDRESS_SIZE_IN_BYTES + INT_SIZE_IN_BYTES;
  }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    System.arraycopy(
      ByteArrays.toByteArray(reserved), 0, rawData, 0, INT_SIZE_IN_BYTES
    );

    Iterator<Inet6Address> iter = addresses.iterator();
    for (
        int i = INT_SIZE_IN_BYTES;
        i < rawData.length;
        i += INET6_ADDRESS_SIZE_IN_BYTES
      ) {
      System.arraycopy(
        ByteArrays.toByteArray(iter.next()), 0,
        rawData, i, INET6_ADDRESS_SIZE_IN_BYTES
      );
    }
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[reserved: ")
      .append(reserved)
      .append("] [addresses:");
    for (Inet6Address addr: addresses) {
      sb.append(" ")
        .append(addr);
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
