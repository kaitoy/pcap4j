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
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.pcap_if;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Pointer;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapNetworkInterface {

  private static final Logger logger
    = LoggerFactory.getLogger(PcapNetworkInterface.class);

  private static final int PCAP_IF_LOOPBACK = 0x00000001;

  private final String name;
  private final String description;
  private final List<PcapAddress> addresses = new ArrayList<PcapAddress>();
  private final boolean loopBack;
  private final boolean local;

  private PcapNetworkInterface(pcap_if pif, boolean local) {
    this.name = pif.name;
    this.description = pif.description;

    for (
      pcap_addr pcapAddr = pif.addresses;
      pcapAddr != null;
      pcapAddr = pcapAddr.next
    ) {
     switch (pcapAddr.addr.sa_family) {
       case Inets.AF_INET:
         addresses.add(PcapIpv4Address.newInstance(pcapAddr));
         break;
       case Inets.AF_INET6:
         addresses.add(PcapIpv6Address.newInstance(pcapAddr));
         break;
       default:
         logger.warn(
           "{} is not supported address family. Ignore it.",
           pcapAddr.addr.sa_family
         );
         break;
      }
    }

    if (pif.flags == PCAP_IF_LOOPBACK) {
      this.loopBack = true;
    }
    else {
      this.loopBack = false;
    }

    this.local = local;
  }

  static PcapNetworkInterface newInstance(pcap_if pif, boolean local) {
    return new PcapNetworkInterface(pif, local);
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
    return loopBack;
  }

  /**
   *
   * @return
   */
  public boolean isLocal() {
    return local;
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

    Pointer handle
      = PcapLibrary.INSTANCE.pcap_open_live(
          this.getName(),
          packetLength,
          mode.getValue(),
          timeoutMillis,
          errbuf
        );
    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return new PcapHandle(handle);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(250);

    sb.append("name: [").append(name)
      .append("] description: [").append(description);

    for (PcapAddress addr: addresses) {
      sb.append("] address: [").append(addr.getAddress());
    }

    sb.append("] loopBack: [").append(loopBack)
      .append("]");
    sb.append("] local: [").append(local)
      .append("]");

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (!(obj instanceof PcapNetworkInterface)) { return false; }

    PcapNetworkInterface other = (PcapNetworkInterface)obj;
    return    this.name.equals(other.getName())
           && this.local == other.isLocal();
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

}
