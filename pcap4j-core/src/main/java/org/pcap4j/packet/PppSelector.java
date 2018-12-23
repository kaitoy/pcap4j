/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class PppSelector extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -1;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Packet object representing a PPP packet.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    byte firstByte = rawData[offset];
    PacketFactory<Packet, DataLinkType> factory =
        PacketFactories.getFactory(Packet.class, DataLinkType.class);
    if (firstByte == (byte) 0xFF) {
      return factory.newInstance(rawData, offset, length, DataLinkType.PPP_SERIAL);
    } else {
      return PppPacket.newPacket(rawData, offset, length);
    }
  }

  private PppSelector() {
    throw new AssertionError();
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }
}
