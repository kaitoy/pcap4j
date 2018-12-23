/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.Serializable;
import java.net.Inet4Address;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class Inet4NetworkAddress implements Serializable {

  /** */
  private static final long serialVersionUID = -8599700451783666420L;

  private final Inet4Address networkAddress;
  private final Inet4Address mask;

  /**
   * @param networkAddress networkAddress
   * @param mask mask
   */
  public Inet4NetworkAddress(Inet4Address networkAddress, Inet4Address mask) {
    this.networkAddress = networkAddress;
    this.mask = mask;
  }

  /** @return networkAddress */
  public Inet4Address getNetworkAddress() {
    return networkAddress;
  }

  /** @return mask */
  public Inet4Address getMask() {
    return mask;
  }
}
