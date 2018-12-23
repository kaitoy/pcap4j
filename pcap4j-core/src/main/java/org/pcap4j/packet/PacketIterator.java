/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Pcap4J.org
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
public final class PacketIterator implements Iterator<Packet> {

  private Packet next;
  private Packet previous = null;

  /** @param p p */
  public PacketIterator(Packet p) {
    this.next = p;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public Packet next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }

    previous = next;
    next = next.getPayload();

    return previous;
  }

  /** @throws UnsupportedOperationException always. */
  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}
