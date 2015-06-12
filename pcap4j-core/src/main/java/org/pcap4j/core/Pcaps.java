/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_if;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.Inet4NetworkAddress;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
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

//  #define PCAP_TSTAMP_PRECISION_MICRO     0       /* use timestamps with microsecond precision, default */
//  #define PCAP_TSTAMP_PRECISION_NANO      1       /* use timestamps with nanosecond precision */
  public static final int PCAP_TSTAMP_PRECISION_MICRO = 0;
  public static final int PCAP_TSTAMP_PRECISION_NANO  = 1;

  private static final Logger logger = LoggerFactory.getLogger(Pcaps.class);

  private Pcaps() { throw new AssertionError(); }

  /**
   *
   * @return a list of PcapNetworkInterfaces.
   * @throws PcapNativeException
   */
  public static
  List<PcapNetworkInterface> findAllDevs() throws PcapNativeException {
    PointerByReference alldevsPP = new PointerByReference();
    PcapErrbuf errbuf = new PcapErrbuf();

    int rc = NativeMappings.pcap_findalldevs(alldevsPP, errbuf);
    if (rc != 0) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Return code: ")
        .append(rc)
        .append(", Message: ")
        .append(errbuf);
      throw new PcapNativeException(sb.toString(), rc);
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

    NativeMappings.pcap_freealldevs(pcapIf.getPointer());

    logger.info("{} NIF(s) found.", ifList.size());
    return ifList;
  }

  /**
   *
   * @param addr
   * @return a PcapNetworkInterface.
   * @throws PcapNativeException
   */
  public static PcapNetworkInterface getDevByAddress(
    InetAddress addr
  ) throws PcapNativeException {
    if (addr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("addr: ").append(addr);
      throw new NullPointerException(sb.toString());
    }

    List<PcapNetworkInterface> allDevs = findAllDevs();
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
   * @param name
   * @return a PcapNetworkInterface.
   * @throws PcapNativeException
   */
  public static PcapNetworkInterface getDevByName(
    String name
  ) throws PcapNativeException {
    if (name == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("name: ").append(name);
      throw new NullPointerException(sb.toString());
    }

    List<PcapNetworkInterface> allDevs = findAllDevs();
    for (PcapNetworkInterface pif: allDevs) {
      if (pif.getName().equals(name)) {
        return pif;
      }
    }

    return null;
  }

  /**
   *
   * @return a name of a network interface.
   * @throws PcapNativeException
   */
  public static String lookupDev() throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer result = NativeMappings.pcap_lookupdev(errbuf);

    if (result == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return result.getWideString(0);
  }

  /**
   *
   * @param devName
   * @return an {@link org.pcap4j.util.Inet4NetworkAddress Inet4NetworkAddress} object.
   * @throws PcapNativeException
   */
  public static Inet4NetworkAddress lookupNet(
    String devName
  ) throws PcapNativeException {
    if (devName == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("devName: ").append(devName);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    IntByReference netp = new IntByReference();
    IntByReference maskp = new IntByReference();
    int rc = NativeMappings.pcap_lookupnet(devName, netp, maskp, errbuf);

    if (rc < 0) {
      throw new PcapNativeException(errbuf.toString(), rc);
    }

    int net = netp.getValue();
    int mask = maskp.getValue();

    return new Inet4NetworkAddress(
                 Inets.itoInetAddress(net), Inets.itoInetAddress(mask)
               );
  }

  /**
   *
   * @param filePath "-" means stdin
   * @return a new PcapHandle object.
   * @throws PcapNativeException
   */
  public static PcapHandle openOffline(
    String filePath
  ) throws PcapNativeException {
    if (filePath == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("filePath: ").append(filePath);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer handle
      = NativeMappings.pcap_open_offline(filePath, errbuf);

    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return new PcapHandle(handle);
  }

  /**
   *
   * @param filePath "-" means stdin
   * @param precision PCAP_TSTAMP_PRECISION_NANO or PCAP_TSTAMP_PRECISION_MICRO
   * @return a new PcapHandle object.
   * @throws PcapNativeException
   */
  public static PcapHandle openOfflineWithTstampPrecision(
    String filePath, int precision
  ) throws PcapNativeException {
    if (filePath == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("filePath: ").append(filePath);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer handle
      = PcapLibrary.INSTANCE.pcap_open_offline_with_tstamp_precision(filePath, precision, errbuf);

    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return new PcapHandle(handle);
  }

  /**
   *
   * @param dlt
   * @param snaplen Snapshot length, which is the number of bytes captured for each packet.
   * @return a new PcapHandle object.
   * @throws PcapNativeException
   */
  public static PcapHandle openDead(
    DataLinkType dlt, int snaplen
  ) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }

    Pointer handle
      = NativeMappings.pcap_open_dead(dlt.value(), snaplen);
    if (handle == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Failed to open a PcapHandle. dlt: ").append(dlt)
        .append(" snaplen: ").append(snaplen);
      throw new PcapNativeException(sb.toString());
    }

    return new PcapHandle(handle);
  }

  /**
   *
   * @param snaplen
   * @param dlt
   * @param bpfExpression
   * @param mode
   * @param netmask
   * @return a {@link org.pcap4j.core.BpfProgram BpfProgram} object.
   * @throws PcapNativeException
   */
  public static BpfProgram compileFilter(
    int snaplen, DataLinkType dlt, String bpfExpression,
    BpfCompileMode mode, Inet4Address netmask
  ) throws PcapNativeException {
    if (
         dlt == null
      || bpfExpression == null
      || mode == null
      || netmask == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt)
        .append(" bpfExpression: ").append(bpfExpression)
        .append(" mode: ").append(mode)
        .append(" netmask: ").append(netmask);
      throw new NullPointerException(sb.toString());
    }

    bpf_program prog = new bpf_program();
    int rc = NativeMappings.pcap_compile_nopcap(
               snaplen, dlt.value(), prog, bpfExpression, mode.getValue(),
               ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0)
             );
    if (rc < 0) {
      throw new PcapNativeException(
                  "Failed to compile the BPF expression: " + bpfExpression,
                  rc
                );
    }
    return new BpfProgram(prog, bpfExpression);
  }

  /**
   * @param name a data link type name, which is a DLT_ name with the DLT_ removed.
   * @return a {@link org.pcap4j.packet.namednumber.DataLinkType DataLinkType} object.
   * @throws PcapNativeException
   */
  public static DataLinkType dataLinkNameToVal(
    String name
  ) throws PcapNativeException {
    if (name == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("name: ").append(name);
      throw new NullPointerException(sb.toString());
    }

    int rc = NativeMappings.pcap_datalink_name_to_val(name);
    if (rc < 0) {
      throw new PcapNativeException(
                  "Failed to convert the data link name to the value: " + name,
                  rc
                );
    }
    return DataLinkType.getInstance(rc);
  }

  /**
   * @param dlt
   * @return data link type name
   * @throws PcapNativeException
   */
  public static String dataLinkTypeToName(
    DataLinkType dlt
  ) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }
    return dataLinkValToName(dlt.value());
  }

  /**
   * @param dataLinkVal
   * @return data link type name
   * @throws PcapNativeException
   */
  public static String dataLinkValToName(
    int dataLinkVal
  ) throws PcapNativeException {
    String name = NativeMappings.pcap_datalink_val_to_name(dataLinkVal);
    if (name == null) {
      throw new PcapNativeException(
                  "Failed to convert the data link value to the name: " + dataLinkVal
                );
    }
    return name;
  }

  /**
   * @param dlt
   * @return a short description of that data link type.
   * @throws PcapNativeException
   */
  public static String dataLinkTypeToDescription(
    DataLinkType dlt
  ) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }
    return dataLinkValToDescription(dlt.value());
  }

  /**
   * @param dataLinkVal
   * @return a short description of that data link type.
   * @throws PcapNativeException
   */
  public static String dataLinkValToDescription(
    int dataLinkVal
  ) throws PcapNativeException {
    String descr = NativeMappings.pcap_datalink_val_to_description(dataLinkVal);
    if (descr == null) {
      throw new PcapNativeException(
                  "Failed to convert the data link value to the description: " + dataLinkVal
                );
    }
    return descr;
  }

  /**
   * @param error
   * @return an error message.
   */
  public static String strError(int error) {
    return NativeMappings.pcap_strerror(error).getString(0);
  }

  /**
   * @return a string giving information about the version of the libpcap library being used;
   *         note that it contains more information than just a version number.
   */
  public static String libVersion() {
    return NativeMappings.pcap_lib_version();
  }

  /**
   *
   * @param inetAddr Inet4Address or Inet6Address
   * @return a string representation of an InetAddress for BPF.
   */
  public static String toBpfString(InetAddress inetAddr){
    if (inetAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("inetAddr: ").append(inetAddr);
      throw new NullPointerException(sb.toString());
    }

    String strAddr = inetAddr.toString();
    return strAddr.substring(strAddr.lastIndexOf("/") + 1);
  }

  /**
   *
   * @param macAddr
   * @return a string representation of a MAC address for BPF.
   */
  public static String toBpfString(MacAddress macAddr) {
    if (macAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("macAddr: ").append(macAddr);
      throw new NullPointerException(sb.toString());
    }

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

