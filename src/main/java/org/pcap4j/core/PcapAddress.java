/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
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

  /**
   *
   * @return
   */
  public InetAddress getAddress();

  /**
   *
   * @return
   */
  public InetAddress getNetmask();

  /**
   *
   * @return
   */
  public InetAddress getBroadcastAddress();

  /**
   *
   * @return
   */
  public InetAddress getDestinationAddress();

}
