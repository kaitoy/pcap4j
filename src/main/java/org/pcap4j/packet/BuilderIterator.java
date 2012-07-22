/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Iterator;
import java.util.NoSuchElementException;
import org.pcap4j.packet.Packet.Builder;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.9
 */
public final class BuilderIterator implements Iterator<Builder> {

  private Builder next;
  private Builder previous = null;

  /**
   *
   * @param p
   */
  public BuilderIterator(Builder b) {
    this.next = b;
  }

  public boolean hasNext() {
    return next != null;
  }

  /**
   * @return
   * @throws NoSuchElementException
   */
  public Builder next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }

    previous = next;
    next = next.getPayloadBuilder();

    return previous;
  }

  /**
   * @throws UnsupportedOperationException
   */
  public void remove() {
    throw new UnsupportedOperationException();
  }

}
