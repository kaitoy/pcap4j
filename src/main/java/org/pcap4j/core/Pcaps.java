/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.pcap_if;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class Pcaps {

//  #define PCAP_ERROR      -1  /* generic error code */
//  #define PCAP_ERROR_BREAK    -2  /* loop terminated by pcap_breakloop */
//  #define PCAP_ERROR_NOT_ACTIVATED  -3  /* the capture needs to be activated */
//  #define PCAP_ERROR_ACTIVATED    -4  /* the operation can't be performed on already activated captures */
//  #define PCAP_ERROR_NO_SUCH_DEVICE -5  /* no such device exists */
//  #define PCAP_ERROR_RFMON_NOTSUP   -6  /* this device doesn't support rfmon (monitor) mode */
//  #define PCAP_ERROR_NOT_RFMON    -7  /* operation supported only in monitor mode */
//  #define PCAP_ERROR_PERM_DENIED    -8  /* no permission to open the device */
//  #define PCAP_ERROR_IFACE_NOT_UP   -9  /* interface isn't up */
//  #define PCAP_WARNING      1 /* generic warning code */
//  #define PCAP_WARNING_PROMISC_NOTSUP 2 /* this device doesn't support promiscuous mode */

  private static final Logger logger = LoggerFactory.getLogger(Pcaps.class);

  private Pcaps() { throw new AssertionError(); }

  /**
   *
   * @return
   * @throws PcapNativeException
   */
  public static
  List<PcapNetworkInterface> findAllDevs() throws PcapNativeException {
    PointerByReference alldevsPP = new PointerByReference();
    PcapErrbuf errbuf = new PcapErrbuf();

    int rc = PcapLibrary.INSTANCE.pcap_findalldevs(alldevsPP, errbuf);
    if (rc != 0) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Return code: ")
        .append(rc)
        .append(", Message: ")
        .append(errbuf);
      throw new PcapNativeException(sb.toString());
    }
    if (errbuf.length() != 0) {
      logger.warn("{}", errbuf);
    }

    Pointer alldevsp = alldevsPP.getValue();
    if (alldevsp == null) {
      logger.info("No NIF was found.");
      return Collections.<PcapNetworkInterface>emptyList();
    }

    pcap_if pcapIf = new pcap_if(alldevsp);

    List<PcapNetworkInterface> ifList = new ArrayList<PcapNetworkInterface>();
    for (pcap_if pif = pcapIf; pif != null; pif = pif.next) {
      ifList.add(PcapNetworkInterface.newInstance(pif, true));
    }

    PcapLibrary.INSTANCE.pcap_freealldevs(pcapIf.getPointer());

    logger.info("{} NIF(s) found.", ifList.size());
    return ifList;
  }

  /**
   *
   * @param addr
   * @return
   * @throws PcapNativeException
   */
  public static PcapNetworkInterface getNifBy(
    InetAddress addr
  ) throws PcapNativeException {
    List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();

    for (PcapNetworkInterface pif: allDevs) {
      for (PcapAddress paddr: pif.getAddresses()) {
        if (paddr.getAddress().equals(addr)) {
          return pif;
        }
      }
    }

    return null;
  }

  /**
   *
   * @return
   * @throws PcapNativeException
   */
  public static String lookupDev() throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer result = PcapLibrary.INSTANCE.pcap_lookupdev(errbuf);

    if (result == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return result.getString(0, true);
  }

  /**
   *
   * @param inetAddr
   * @return
   */
  public static String toBpfString (InetAddress inetAddr){
    // TODO IPv6
    return inetAddr.toString().replaceFirst("\\A.*/", "");
  }

  /**
   *
   * @param macAddr
   * @return
   */
  public static String toBpfString(MacAddress macAddr) {
    StringBuffer buf = new StringBuffer();
    byte[] address = macAddr.getAddress();

    for (int i = 0; i < address.length; i++) {
      buf.append(String.format("%02x", address[i]));
      buf.append(":");
    }
    buf.deleteCharAt(buf.length() - 1);

    return buf.toString();
  }
}

