/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class IpSelector extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -1;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Packet object representing an IP (v4 or v6) packet.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    int ipVersion = (rawData[offset] >> 4) & 0x0f;
    PacketFactory<Packet, EtherType> factory =
        PacketFactories.getFactory(Packet.class, EtherType.class);
    if (ipVersion == IpVersion.IPV4.value().intValue()) {
      return factory.newInstance(rawData, offset, length, EtherType.IPV4);
    }
    if (ipVersion == IpVersion.IPV6.value().intValue()) {
      return factory.newInstance(rawData, offset, length, EtherType.IPV6);
    } else {
      return PacketFactories.getFactory(Packet.class, NotApplicable.class)
          .newInstance(rawData, offset, length, NotApplicable.UNKNOWN);
    }
  }

  private IpSelector() {
    throw new AssertionError();
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }
}
