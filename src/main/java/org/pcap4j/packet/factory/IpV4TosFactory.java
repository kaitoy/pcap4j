/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public interface IpV4TosFactory {

  // /* must implement. called by IpV4TosFactories. */
  // public static IpV4TosFactory getInstance();

  /**
   *
   * @param value
   * @return
   */
  public IpV4Tos newTos(byte value);

}
