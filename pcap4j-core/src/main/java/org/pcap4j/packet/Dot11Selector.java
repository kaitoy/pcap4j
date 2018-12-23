/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11Selector extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -4770251478963995769L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Packet object representing an IEEE802.11 packet.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    Dot11FrameControl ctrl = Dot11FrameControl.newInstance(rawData, offset, length);
    PacketFactory<Packet, Dot11FrameType> factory =
        PacketFactories.getFactory(Packet.class, Dot11FrameType.class);
    return factory.newInstance(rawData, offset, length, ctrl.getType());
  }

  private Dot11Selector() {
    throw new AssertionError();
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }
}
