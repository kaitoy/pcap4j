/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.pcap_addr;
import org.pcap4j.core.NativeMappings.pcap_if;
import org.pcap4j.core.NativeMappings.timeval;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.jna.NativeLong;
import com.sun.jna.Platform;
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
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   *
   * @return description
   */
  public String getDescription() {
    return description;
  }

  /**
   *
   * @return addresses
   */
  public List<PcapAddress> getAddresses() {
    return new ArrayList<PcapAddress>(addresses);
  }

  /**
   *
   * @return true if the network interface represented by this object
   *         is a loop back interface; false otherwise.
   */
  public boolean isLoopBack() {
    return loopBack;
  }

  /**
   *
   * @return true if the network interface represented by this object
   *         is a local interface; false otherwise.
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
     * @return value
     */
    public int getValue() {
      return value;
    }
  }

  /**
   *
   * @param maxCaptureLength
   * @param mode
   * @param timeoutMillis Read timeout. Most OSs buffer packets.
   *        The OSs pass the packets to Pcap4j after the buffer gets full
   *        or the read timeout expires.
   *        Must be non-negative. May be ignored by some OSs.
   *        0 means disable buffering on Solaris.
   *        0 means infinite on the other OSs.
   *        1 through 9 means infinite on Solaris.
   * @return an opened PcapHandle.
   * @throws PcapNativeException
   */
  public PcapHandle openLive(
    int maxCaptureLength, PromiscuousMode mode, int timeoutMillis
  ) throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();

//    Pointer handle
//      = PcapLibrary.INSTANCE.pcap_open_live(
//          name,
//          maxCaptureLength,
//          mode.getValue(),
//          timeoutMillis,
//          errbuf
//        );
    Pointer handle
      = NativeMappings.pcap_open_live(
          name,
          maxCaptureLength,
          mode.getValue(),
          timeoutMillis,
          errbuf
        );

    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    if (timeoutMillis == 0 && Platform.isSolaris()) {
      // disable buffering
      timeval to = new timeval();
      to.tv_sec = new NativeLong(0);
      to.tv_usec = new NativeLong(0);

      int rc = PcapLibrary.INSTANCE.strioctl(
                 NativeMappings.getFdFromPcapT(handle),
                 NativeMappings.SBIOCSTIME,
                 to.size(),
                 to.getPointer()
               );

      if (rc < 0) {
//        throw new PcapNativeException(
//                "SBIOCSTIME: "
//                  + PcapLibrary.INSTANCE.pcap_strerror(
//                      NativeMappings.ERRNO_P.getInt(0)
//                    ).getString(0)
//              );
        throw new PcapNativeException(
                "SBIOCSTIME: "
                  + NativeMappings.pcap_strerror(
                      NativeMappings.ERRNO_P.getInt(0)
                    ).getString(0)
              );
      }
    }

    return new PcapHandle(handle, true);
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
