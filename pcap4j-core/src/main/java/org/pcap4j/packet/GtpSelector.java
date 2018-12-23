/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.GtpV1Packet.ProtocolType;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class GtpSelector extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 5081921978086270980L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Packet object representing an GTP (version x) packet.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    int ver = (rawData[offset] >> 5) & 0x07;
    ProtocolType pt = ProtocolType.getInstance((rawData[offset] & 0x10) != 0);
    switch (ver) {
      case 1:
        switch (pt) {
          case GTP:
            return GtpV1Packet.newPacket(rawData, offset, length);
          case GTP_PRIME:
          default:
            return PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(rawData, offset, length, NotApplicable.UNKNOWN);
        }
      case 2:
      default:
        return PacketFactories.getFactory(Packet.class, NotApplicable.class)
            .newInstance(rawData, offset, length, NotApplicable.UNKNOWN);
    }
  }

  private GtpSelector() {
    throw new AssertionError();
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }
}
