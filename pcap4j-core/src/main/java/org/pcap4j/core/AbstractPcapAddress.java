/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;
import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.sockaddr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
abstract class AbstractPcapAddress implements PcapAddress {

  private static final Logger logger = LoggerFactory.getLogger(AbstractPcapAddress.class);

  private final InetAddress address;
  private final InetAddress netmask;
  private final InetAddress broadcastAddr;
  private final InetAddress dstAddr; // for point-to-point interface

  protected AbstractPcapAddress(pcap_addr pcapAddr, short saFamily, String devName) {
    if (pcapAddr == null) {
      throw new NullPointerException();
    }

    if (pcapAddr.addr != null && pcapAddr.addr.getSaFamily() != Inets.AF_UNSPEC) {
      if (pcapAddr.addr.getSaFamily() != saFamily) {
        warn(pcapAddr.addr.getSaFamily(), saFamily, devName, "addr");
        this.address = null;
      } else {
        this.address = ntoInetAddress(pcapAddr.addr);
      }
    } else {
      this.address = null;
    }

    if (pcapAddr.netmask != null && pcapAddr.netmask.getSaFamily() != Inets.AF_UNSPEC) {
      if (pcapAddr.netmask.getSaFamily() != saFamily) {
        warn(pcapAddr.netmask.getSaFamily(), saFamily, devName, "netmask");
        this.netmask = null;
      } else {
        this.netmask = ntoInetAddress(pcapAddr.netmask);
      }
    } else {
      this.netmask = null;
    }

    if (pcapAddr.broadaddr != null && pcapAddr.broadaddr.getSaFamily() != Inets.AF_UNSPEC) {
      if (pcapAddr.broadaddr.getSaFamily() != saFamily) {
        warn(pcapAddr.broadaddr.getSaFamily(), saFamily, devName, "broadaddr");
        this.broadcastAddr = null;
      } else {
        this.broadcastAddr = ntoInetAddress(pcapAddr.broadaddr);
      }
    } else {
      this.broadcastAddr = null;
    }

    if (pcapAddr.dstaddr != null && pcapAddr.dstaddr.getSaFamily() != Inets.AF_UNSPEC) {
      if (pcapAddr.dstaddr.getSaFamily() != saFamily) {
        warn(pcapAddr.dstaddr.getSaFamily(), saFamily, devName, "dstaddr");
        this.dstAddr = null;
      } else {
        this.dstAddr = ntoInetAddress(pcapAddr.dstaddr);
      }
    } else {
      this.dstAddr = null;
    }
  }

  private void warn(short actualSaFamily, short expectedSaFamily, String devName, String field) {
    if (logger.isWarnEnabled()) {
      logger.warn(
          "Couldn't analyze an address. "
              + "devName: {}, field: {}, actual saFamily: {}, expected saFamily: {}",
          devName,
          field,
          actualSaFamily,
          expectedSaFamily);
    }
  }

  @Override
  public InetAddress getAddress() {
    return address;
  }

  @Override
  public InetAddress getNetmask() {
    return netmask;
  }

  @Override
  public InetAddress getBroadcastAddress() {
    return broadcastAddr;
  }

  @Override
  public InetAddress getDestinationAddress() {
    return dstAddr;
  }

  protected abstract InetAddress ntoInetAddress(sockaddr sa);

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(190);

    sb.append("address: [")
        .append(address)
        .append("] netmask: [")
        .append(netmask)
        .append("] broadcastAddr: [")
        .append(broadcastAddr)
        .append("] dstAddr [")
        .append(dstAddr)
        .append("]");

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;

    AbstractPcapAddress other = (AbstractPcapAddress) obj;
    if (address == null) {
      if (other.address != null) return false;
    } else if (!address.equals(other.address)) return false;
    if (broadcastAddr == null) {
      if (other.broadcastAddr != null) return false;
    } else if (!broadcastAddr.equals(other.broadcastAddr)) return false;
    if (dstAddr == null) {
      if (other.dstAddr != null) return false;
    } else if (!dstAddr.equals(other.dstAddr)) return false;
    if (netmask == null) {
      if (other.netmask != null) return false;
    } else if (!netmask.equals(other.netmask)) return false;

    return true;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((address == null) ? 0 : address.hashCode());
    result = prime * result + ((broadcastAddr == null) ? 0 : broadcastAddr.hashCode());
    result = prime * result + ((dstAddr == null) ? 0 : dstAddr.hashCode());
    result = prime * result + ((netmask == null) ? 0 : netmask.hashCode());
    return result;
  }
}
