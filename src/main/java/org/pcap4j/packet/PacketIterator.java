package org.pcap4j.packet;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class PacketIterator implements Iterator<Packet> {

  private Packet nextPacket;
  private Packet previousPacket = null;

  public PacketIterator(Packet p) {
    this.nextPacket = p;
  }

  public boolean hasNext() {
    return nextPacket != null;
  }

  public Packet next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }

    previousPacket = nextPacket;
    nextPacket = nextPacket.getPayload();

    return previousPacket;
  }

  public void remove() {
    throw new UnsupportedOperationException();
  }

}
