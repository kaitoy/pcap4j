/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public interface IpV6TrafficClassFactory {

  // /* must implement. called by IpV6TrafficClassFactories. */
  // public static IpV6TrafficClassFactory getInstance();

  /**
   *
   * @param value
   * @return a new IpV6TrafficClass object.
   */
  public IpV6TrafficClass newTrafficClass(byte value);

}
