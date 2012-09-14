/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.Inet4Address;
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

  static PcapIpv4Address newInstance(pcap_addr pcapAddr) {
    return new PcapIpv4Address(pcapAddr);
  }

  @Override
  protected Inet4Address ntoInetAddress(sockaddr sa) {
    sockaddr_in addr = new sockaddr_in(sa.getPointer());
    return Inets.ntoInetAddress(addr.sin_addr);
  }

  @Override
  public Inet4Address getAddress() {
    return (Inet4Address)super.getAddress();
  }

  @Override
  public Inet4Address getNetmask() {
    return (Inet4Address)super.getNetmask();
  }

  @Override
  public Inet4Address getBroadcastAddress() {
    return getBroadcastAddress();
  }

  @Override
  public Inet4Address getDestinationAddress() {
    return getDestinationAddress();
  }

}
