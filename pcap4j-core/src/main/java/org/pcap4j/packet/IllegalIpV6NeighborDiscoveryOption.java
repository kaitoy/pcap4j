/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.util.ByteArrays;


/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IllegalIpV6NeighborDiscoveryOption
implements IpV6NeighborDiscoveryOption {

  /**
   *
   */
  private static final long serialVersionUID = 2715909582897939970L;

  private final byte[] rawData;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData
   * @param offset
   * @param length
   * @return a new IllegalIpV6NeighborDiscoveryOption object.
   */
  public static IllegalIpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, int offset, int length
  ) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalIpV6NeighborDiscoveryOption(rawData, offset, length);
  }

  private IllegalIpV6NeighborDiscoveryOption(byte[] rawData, int offset, int length) {
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  @Override
  public IpV6NeighborDiscoveryOptionType getType() { return null; }

  @Override
  public int length() { return rawData.length; }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Illegal Raw Data: 0x")
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
