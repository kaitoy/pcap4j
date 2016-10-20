/*_##########################################################################
  _##
  _##  Copyright (C) 2018  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.producer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

/**
 * Skeletal Implementation of {@link PacketSupplier}.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public final class RootPacketSupplier implements PacketSupplier {

  private final PcapHandle handle;

  /**
   *
   * @param handle handle
   */
  public RootPacketSupplier(PcapHandle handle) {
    this.handle = handle;
  }

  @Override
  public Packet get() throws PcapNativeException, InterruptedException {
    try {
      return handle.getNextPacketEx();
    } catch (EOFException | TimeoutException | NotOpenException e) {
      InterruptedException iex = new InterruptedException();
      iex.initCause(e);
      throw iex;
    }
  }

}
