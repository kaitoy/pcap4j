/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class PacketIterator implements Iterator<Packet> {

  private Packet nextPacket;
  private Packet previousPacket = null;

  /**
   *
   * @param p
   */
  public PacketIterator(Packet p) {
    this.nextPacket = p;
  }

  /**
   * @return
   */
  public boolean hasNext() {
    return nextPacket != null;
  }

  /**
   * @return
   */
  public Packet next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }

    previousPacket = nextPacket;
    nextPacket = nextPacket.getPayload();

    return previousPacket;
  }

  /**
   *
   */
  public void remove() {
    throw new UnsupportedOperationException();
  }

}
