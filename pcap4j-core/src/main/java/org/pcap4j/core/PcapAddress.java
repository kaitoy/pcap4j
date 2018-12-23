/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public interface PcapAddress {

  /** @return address or null */
  public InetAddress getAddress();

  /** @return netmask or null */
  public InetAddress getNetmask();

  /** @return broadcast address or null */
  public InetAddress getBroadcastAddress();

  /** @return destination address or null */
  public InetAddress getDestinationAddress();
}
