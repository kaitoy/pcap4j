/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.0
 */
public final class SshPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 1L;

  private static final Logger logger = LoggerFactory.getLogger(SshPacket.class);

  /**
   *
   * @param rawData
   * @return a new Packet object representing an SSH packet.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static Packet newPacket(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    try {
      return Ssh2BinaryPacket.newPacket(rawData);
    } catch (IllegalRawDataException e) {
      logger.debug("rawData seems not SSH2 binary packet.", e);
      return Ssh2VersionExchangePacket.newPacket(rawData);
    }
  }

  private SshPacket() { throw new AssertionError(); }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }

}
