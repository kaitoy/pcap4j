/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;


import java.net.InetAddress;

import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.sockaddr;

abstract class AbstractPcapAddress implements PcapAddress {

  private final InetAddress address;
  private final InetAddress netmask;
  private final InetAddress broadcastAddr;
  private final InetAddress dstAddr; // for point- to-point interface

  protected AbstractPcapAddress(pcap_addr pcapAddr) {
    this.address = ntoInetAddress(pcapAddr.addr);

    if (pcapAddr.netmask != null && pcapAddr.netmask.sa_family != Inet.AF_UNSPEC) {
      if (pcapAddr.addr.sa_family != pcapAddr.netmask.sa_family) {
        throw new AssertionError();
      }
      this.netmask = ntoInetAddress(pcapAddr.netmask);
    }
    else {
      this.netmask = null;
    }

    if (pcapAddr.broadaddr != null && pcapAddr.broadaddr.sa_family != Inet.AF_UNSPEC) {
      if (pcapAddr.addr.sa_family != pcapAddr.broadaddr.sa_family) {
        throw new AssertionError();
      }
      this.broadcastAddr = ntoInetAddress(pcapAddr.broadaddr);
    }
    else {
      this.broadcastAddr = null;
    }

    if (pcapAddr.dstaddr != null && pcapAddr.dstaddr.sa_family != Inet.AF_UNSPEC) {
      if (pcapAddr.addr.sa_family != pcapAddr.dstaddr.sa_family) {
        throw new AssertionError();
      }
      this.dstAddr = ntoInetAddress(pcapAddr.dstaddr);
    }
    else {
      this.dstAddr = null;
    }
  }

  public InetAddress getAddress() {
    return address;
  }

  public InetAddress getNetmask() {
    return netmask;
  }

  public InetAddress getBroadcastAddress() {
    return broadcastAddr;
  }

  public InetAddress getDestinationAddress() {
    return dstAddr;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("address: [").append(address)
      .append("] netmask: [").append(netmask)
      .append("] broadcastAddr: [").append(broadcastAddr)
      .append("] dstAddr [").append(dstAddr)
      .append("]");

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (!this.getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }

    AbstractPcapAddress addr = this.getClass().cast(obj);
    return    this.address.equals(addr.address)
           && this.netmask.equals(addr.netmask)
           && this.broadcastAddr.equals(addr.broadcastAddr)
           && this.dstAddr.equals(addr.dstAddr);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  protected abstract InetAddress ntoInetAddress(sockaddr sa);

}
