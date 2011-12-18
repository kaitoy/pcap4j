/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;

public interface PcapAddress {

  public InetAddress getAddress();
  public InetAddress getNetmask();
  public InetAddress getBroadcastAddress();
  public InetAddress getDestinationAddress();

}
