/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * A socket address (i.e. a pair of an IP address and a port).
 * @author Kaito Yamada
 * @since pcap4j 1.7.2
 */
public final class SocketAddress implements Serializable {

  private static final long serialVersionUID = 3482452189517932568L;
  private final InetAddress address;
  private final Short port;

  /**
   * @param address address
   * @param port port
   */
  public SocketAddress(InetAddress address, Short port) {
    this.address = address;
    this.port = port;
  }

  /**
   * @return address
   */
  public InetAddress getAddress() {
    return address;
  }

  /**
   * @return port
   */
  public Short getPort() {
    return port;
  }

}
