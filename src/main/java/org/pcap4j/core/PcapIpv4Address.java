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
import org.pcap4j.core.NativeMappings.sockaddr_in;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapIpv4Address extends AbstractPcapAddress {

  private PcapIpv4Address(pcap_addr pcapAddr) {
    super(pcapAddr);
  }

  /**
   *
   * @param pcapAddr
   * @return
   */
  static PcapIpv4Address newInstance(pcap_addr pcapAddr) {
    return new PcapIpv4Address(pcapAddr);
  }

  @Override
  protected InetAddress ntoInetAddress(sockaddr sa) {
    sockaddr_in addr = new sockaddr_in(sa.getPointer());
    return Inets.ntoInetAddress(addr.sin_addr);
  }

}
