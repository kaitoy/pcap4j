/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -1;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData
   * @param offset
   * @param length
   * @return a new Packet object representing an IP (v4 or v6) packet.
   * @throws IllegalRawDataException
   */
  public static Packet newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    int ipVersion = (rawData[offset] >> 4) & 0x0f;
    if (ipVersion == IpVersion.IPV4.value().intValue()) {
      return IpV4Packet.newPacket(rawData, offset, length);
    }
    if (ipVersion == IpVersion.IPV6.value().intValue()) {
      return IpV6Packet.newPacket(rawData, offset, length);
    }
    else {
      return UnknownPacket.newPacket(rawData, offset, length);
    }
  }

  private IpPacket() { throw new AssertionError(); }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }

}
