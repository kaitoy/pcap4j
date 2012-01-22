/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.pcap_if;
import com.sun.jna.Pointer;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapNetworkInterface {

  private static final Logger logger
    = Logger.getLogger(PcapNetworkInterface.class);

  private static final int PCAP_IF_LOOPBACK = 0x00000001;

  private final String name;
  private final String description;
  private final List<PcapAddress> addresses = new ArrayList<PcapAddress>();
  private final boolean isLoopBack;

  private PcapNetworkInterface(pcap_if pif) {
    this.name = pif.name;
    this.description = pif.description;

    for (
      pcap_addr pcapAddr = pif.addresses;
      pcapAddr != null;
      pcapAddr = pcapAddr.next
    ) {
     switch (pcapAddr.addr.sa_family) {
       case Inet.AF_INET:
         addresses.add(PcapIpv4Address.newInstance(pcapAddr));
         break;
       case Inet.AF_INET6:
         addresses.add(PcapIpv6Address.newInstance(pcapAddr));
         break;
       default:
         logger.warn(
           pcapAddr.addr.sa_family
             + " is not supported address family. Ignore it."
         );
         break;
      }
    }

    if (pif.flags == PCAP_IF_LOOPBACK) {
      this.isLoopBack = true;
    }
    else {
      this.isLoopBack = false;
    }
  }

  static PcapNetworkInterface newInstance(pcap_if pif) {
    return new PcapNetworkInterface(pif);
  }

  /**
   *
   * @return
   */
  public String getName() {
    return name;
  }

  /**
   *
   * @return
   */
  public String getDescription() {
    return description;
  }

  /**
   *
   * @return
   */
  public List<PcapAddress> getAddresses() {
    return Collections.unmodifiableList(addresses);
  }

  /**
   *
   * @return
   */
  public boolean isLoopBack() {
    return isLoopBack;
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public enum PromiscuousMode {
    PROMISCUOUS(1),
    NONPROMISCUOUS(0);

    private final int value;

    private PromiscuousMode(int value) {
      this.value = value;
    }

    /**
     *
     * @return
     */
    public int getValue() {
      return value;
    }
  }

  /**
   *
   * @param packetLength
   * @param mode
   * @param timeoutMillis
   * @return
   * @throws PcapNativeException
   */
  public PcapHandle openLive(
    int packetLength, PromiscuousMode mode, int timeoutMillis
  ) throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();

    Pointer ifaceHandle
      = PcapLibrary.INSTANCE.pcap_open_live(
          this.getName(),
          packetLength,
          mode.getValue(),
          timeoutMillis,
          errbuf
        );
    if (ifaceHandle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.getMessage());
    }

    return new PcapHandle(ifaceHandle);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append(name).append("(").append(description).append(")");

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (!this.getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }

    PcapNetworkInterface other = this.getClass().cast(obj);
    return    this.name.equals(other.getName())
           && this.description.equals(other.description);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

}
