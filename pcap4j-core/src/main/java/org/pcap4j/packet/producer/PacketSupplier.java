/*_##########################################################################
  _##
  _##  Copyright (C) 2018  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.producer;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

/**
 * Represents a supplier of {@link Packet} objects.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public interface PacketSupplier {

  /**
   *
   * @return a packet instance
   * @throws InterruptedException if interrupted.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public Packet get() throws PcapNativeException, InterruptedException;

}
