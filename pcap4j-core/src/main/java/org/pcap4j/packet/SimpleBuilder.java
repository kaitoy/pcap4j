/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.AbstractPacket.AbstractBuilder;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class SimpleBuilder extends AbstractBuilder {

  private Packet packet;

  /** */
  public SimpleBuilder() {}

  /** @param packet packet */
  public SimpleBuilder(Packet packet) {
    this.packet = packet;
  }

  /**
   * @param packet packet
   * @return SimpleBuilder
   */
  public SimpleBuilder packet(Packet packet) {
    this.packet = packet;
    return this;
  }

  @Override
  public Packet build() {
    return packet;
  }
}
