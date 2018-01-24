/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
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
implements IpV6NeighborDiscoveryOption, IllegalRawDataHolder {

  /**
   *
   */
  private static final long serialVersionUID = -6156417526745835637L;

  private final IpV6NeighborDiscoveryOptionType type;
  private final byte[] rawData;
  private final IllegalRawDataException cause;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param cause cause
   * @return a new IllegalIpV6NeighborDiscoveryOption object.
   */
  public static IllegalIpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    if (cause == null) {
      throw new NullPointerException("cause is null.");
    }
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalIpV6NeighborDiscoveryOption(rawData, offset, length, cause);
  }

  private IllegalIpV6NeighborDiscoveryOption(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    this.type = IpV6NeighborDiscoveryOptionType.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
    this.cause = cause;
  }

  @Override
  public IpV6NeighborDiscoveryOptionType getType() { return type; }

  @Override
  public int length() { return rawData.length; }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  @Override
  public IllegalRawDataException getCause() {
    return cause;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Type: ")
      .append(type)
      .append("] [Illegal Raw Data: 0x")
      .append(ByteArrays.toHexString(rawData, ""))
      .append("] [cause: ")
      .append(cause)
      .append("]");
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
    IllegalIpV6NeighborDiscoveryOption other = (IllegalIpV6NeighborDiscoveryOption) obj;
    if (!cause.equals(other.cause)) {
      return false;
    }
    if (!Arrays.equals(rawData, other.rawData)) {
      return false;
    }
    return true;
  }

}
