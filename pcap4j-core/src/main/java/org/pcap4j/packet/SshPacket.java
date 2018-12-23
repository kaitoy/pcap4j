/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.0
 */
public final class SshPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 1L;

  private static final Logger logger = LoggerFactory.getLogger(SshPacket.class);

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Packet object representing an SSH packet.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Packet newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    // This will be done by actual packet classes.
    // ByteArrays.validateBounds(rawData, offset, length);
    try {
      return Ssh2VersionExchangePacket.newPacket(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      logger.debug("rawData seems not SSH2 version exchange packet.", e);
      return Ssh2BinaryPacket.newPacket(rawData, offset, length);
    }
  }

  private SshPacket() {
    throw new AssertionError();
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }
}
