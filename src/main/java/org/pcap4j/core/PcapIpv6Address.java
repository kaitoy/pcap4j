/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;
import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.sockaddr;
import org.pcap4j.core.NativeMappings.sockaddr_in6;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapIpv6Address extends AbstractPcapAddress {

  private PcapIpv6Address(pcap_addr pcapAddr) {
    super(pcapAddr);
  }

  /**
   *
   * @param pcapAddr
   * @return
   */
  static PcapIpv6Address newInstance(pcap_addr pcapAddr) {
    return new PcapIpv6Address(pcapAddr);
  }

  @Override
  protected InetAddress ntoInetAddress(sockaddr sa) {
    sockaddr_in6 addr = new sockaddr_in6(sa.getPointer());
    return Inets.ntoInetAddress(addr.sin6_addr);
  }

}
