/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NA;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.1
 */
public final class StaticUnknownPacketFactory
extends AbstractStaticPacketFactory<NA> {

  private static final StaticUnknownPacketFactory INSTANCE
    = new StaticUnknownPacketFactory();

  private StaticUnknownPacketFactory() {};

  /**
   *
   * @return the singleton instance of StaticUnknownPacketFactory.
   */
  public static StaticUnknownPacketFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public Packet newInstance(byte[] rawData, NA number) {
    return super.newInstance(rawData, number);
  }

  @Override
  @Deprecated
  public Class<? extends Packet> getTargetClass(NA number) {
    return super.getTargetClass(number);
  }

}
