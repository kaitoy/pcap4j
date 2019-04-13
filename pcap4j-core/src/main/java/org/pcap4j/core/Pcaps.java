/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
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
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.Inet4NetworkAddress;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class Pcaps {

  private static final Logger logger = LoggerFactory.getLogger(Pcaps.class);
  private static final Object lock = new Object();

  private Pcaps() {
    throw new AssertionError();
  }

  /**
   * Gets all devices.
   *
   * @return a list of PcapNetworkInterfaces.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static List<PcapNetworkInterface> findAllDevs() throws PcapNativeException {
    PointerByReference alldevsPP = new PointerByReference();
    PcapErrbuf errbuf = new PcapErrbuf();

    List<PcapNetworkInterface> ifList = new ArrayList<PcapNetworkInterface>();
    synchronized (lock) {
      int rc = NativeMappings.pcap_findalldevs(alldevsPP, errbuf);
      if (rc != 0) {
        StringBuilder sb = new StringBuilder(50);
        sb.append("Return code: ").append(rc).append(", Message: ").append(errbuf);
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

      for (pcap_if pif = pcapIf; pif != null; pif = pif.next) {
        ifList.add(PcapNetworkInterface.newInstance(pif, true));
      }

      NativeMappings.pcap_freealldevs(pcapIf.getPointer());
    }

    logger.info("{} NIF(s) found.", ifList.size());
    return ifList;
  }

  /**
   * Gets a device by IP address.
   *
   * @param addr addr
   * @return a PcapNetworkInterface.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapNetworkInterface getDevByAddress(InetAddress addr) throws PcapNativeException {
    if (addr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("addr: ").append(addr);
      throw new NullPointerException(sb.toString());
    }

    List<PcapNetworkInterface> allDevs = findAllDevs();
    for (PcapNetworkInterface pif : allDevs) {
      for (PcapAddress paddr : pif.getAddresses()) {
        if (paddr.getAddress().equals(addr)) {
          return pif;
        }
      }
    }

    return null;
  }

  /**
   * Gets a device by name.
   *
   * @param name name
   * @return a PcapNetworkInterface.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapNetworkInterface getDevByName(String name) throws PcapNativeException {
    if (name == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("name: ").append(name);
      throw new NullPointerException(sb.toString());
    }

    List<PcapNetworkInterface> allDevs = findAllDevs();
    for (PcapNetworkInterface pif : allDevs) {
      if (pif.getName().equals(name)) {
        return pif;
      }
    }

    return null;
  }

  /**
   * @return a name of a network interface.
   * @throws PcapNativeException if an error occurs in the pcap native library.
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
   * @param devName devName
   * @return an {@link org.pcap4j.util.Inet4NetworkAddress Inet4NetworkAddress} object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static Inet4NetworkAddress lookupNet(String devName) throws PcapNativeException {
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

    return new Inet4NetworkAddress(Inets.itoInetAddress(net), Inets.itoInetAddress(mask));
  }

  /**
   * @param filePath "-" means stdin
   * @return a new PcapHandle object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapHandle openOffline(String filePath) throws PcapNativeException {
    if (filePath == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("filePath: ").append(filePath);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer handle = NativeMappings.pcap_open_offline(filePath, errbuf);

    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return new PcapHandle(handle, TimestampPrecision.MICRO);
  }

  /**
   * @param filePath "-" means stdin
   * @param precision precision
   * @return a new PcapHandle object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapHandle openOffline(String filePath, TimestampPrecision precision)
      throws PcapNativeException {
    if (filePath == null || precision == null) {
      StringBuilder sb =
          new StringBuilder()
              .append("filePath: ")
              .append(filePath)
              .append(" precision: ")
              .append(precision);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    Pointer handle;
    try {
      handle =
          PcapLibrary.INSTANCE.pcap_open_offline_with_tstamp_precision(
              filePath, precision.getValue(), errbuf);
    } catch (UnsatisfiedLinkError e) {
      throw new PcapNativeException(
          "pcap_open_offline_with_tstamp_precision is not supported by the pcap library"
              + " installed in this environment.");
    }

    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    return new PcapHandle(handle, precision);
  }

  /**
   * @param dlt dlt
   * @param snaplen Snapshot length, which is the number of bytes captured for each packet.
   * @return a new PcapHandle object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapHandle openDead(DataLinkType dlt, int snaplen) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }

    Pointer handle = NativeMappings.pcap_open_dead(dlt.value(), snaplen);
    if (handle == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Failed to open a PcapHandle. dlt: ")
          .append(dlt)
          .append(" snaplen: ")
          .append(snaplen);
      throw new PcapNativeException(sb.toString());
    }

    return new PcapHandle(handle, TimestampPrecision.MICRO);
  }

  /**
   * @param dlt dlt
   * @param snaplen Snapshot length, which is the number of bytes captured for each packet.
   * @param precision precision
   * @return a new PcapHandle object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static PcapHandle openDead(DataLinkType dlt, int snaplen, TimestampPrecision precision)
      throws PcapNativeException {
    if (dlt == null || precision == null) {
      StringBuilder sb =
          new StringBuilder().append("dlt: ").append(dlt).append(" precision: ").append(precision);
      throw new NullPointerException(sb.toString());
    }

    Pointer handle;
    try {
      handle =
          PcapLibrary.INSTANCE.pcap_open_dead_with_tstamp_precision(
              dlt.value(), snaplen, precision.getValue());
    } catch (UnsatisfiedLinkError e) {
      throw new PcapNativeException(
          "pcap_open_dead_with_tstamp_precision is not supported by the pcap library"
              + " installed in this environment.");
    }

    if (handle == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("Failed to open a PcapHandle. dlt: ")
          .append(dlt)
          .append(" snaplen: ")
          .append(snaplen)
          .append(" precision: ")
          .append(precision);
      throw new PcapNativeException(sb.toString());
    }

    return new PcapHandle(handle, precision);
  }

  /**
   * @param snaplen snaplen
   * @param dlt dlt
   * @param bpfExpression bpfExpression
   * @param mode mode
   * @param netmask netmask
   * @return a {@link org.pcap4j.core.BpfProgram BpfProgram} object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static BpfProgram compileFilter(
      int snaplen,
      DataLinkType dlt,
      String bpfExpression,
      BpfCompileMode mode,
      Inet4Address netmask)
      throws PcapNativeException {
    if (dlt == null || bpfExpression == null || mode == null || netmask == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ")
          .append(dlt)
          .append(" bpfExpression: ")
          .append(bpfExpression)
          .append(" mode: ")
          .append(mode)
          .append(" netmask: ")
          .append(netmask);
      throw new NullPointerException(sb.toString());
    }

    bpf_program prog = new bpf_program();
    int rc =
        NativeMappings.pcap_compile_nopcap(
            snaplen,
            dlt.value(),
            prog,
            bpfExpression,
            mode.getValue(),
            ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0));
    if (rc < 0) {
      throw new PcapNativeException("Failed to compile the BPF expression: " + bpfExpression, rc);
    }
    return new BpfProgram(prog, bpfExpression);
  }

  /**
   * @param name a data link type name, which is a DLT_ name with the DLT_ removed.
   * @return a {@link org.pcap4j.packet.namednumber.DataLinkType DataLinkType} object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static DataLinkType dataLinkNameToVal(String name) throws PcapNativeException {
    if (name == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("name: ").append(name);
      throw new NullPointerException(sb.toString());
    }

    int rc = NativeMappings.pcap_datalink_name_to_val(name);
    if (rc < 0) {
      throw new PcapNativeException(
          "Failed to convert the data link name to the value: " + name, rc);
    }
    return DataLinkType.getInstance(rc);
  }

  /**
   * @param dlt dlt
   * @return data link type name
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static String dataLinkTypeToName(DataLinkType dlt) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }
    return dataLinkValToName(dlt.value());
  }

  /**
   * @param dataLinkVal dataLinkVal
   * @return data link type name
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static String dataLinkValToName(int dataLinkVal) throws PcapNativeException {
    String name = NativeMappings.pcap_datalink_val_to_name(dataLinkVal);
    if (name == null) {
      throw new PcapNativeException(
          "Failed to convert the data link value to the name: " + dataLinkVal);
    }
    return name;
  }

  /**
   * @param dlt dlt
   * @return a short description of that data link type.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static String dataLinkTypeToDescription(DataLinkType dlt) throws PcapNativeException {
    if (dlt == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("dlt: ").append(dlt);
      throw new NullPointerException(sb.toString());
    }
    return dataLinkValToDescription(dlt.value());
  }

  /**
   * @param dataLinkVal dataLinkVal
   * @return a short description of that data link type.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   */
  public static String dataLinkValToDescription(int dataLinkVal) throws PcapNativeException {
    String descr = NativeMappings.pcap_datalink_val_to_description(dataLinkVal);
    if (descr == null) {
      throw new PcapNativeException(
          "Failed to convert the data link value to the description: " + dataLinkVal);
    }
    return descr;
  }

  /**
   * @param error error
   * @return an error message.
   */
  public static String strError(int error) {
    return NativeMappings.pcap_strerror(error).getString(0);
  }

  /**
   * @return a string giving information about the version of the libpcap library being used; note
   *     that it contains more information than just a version number.
   */
  public static String libVersion() {
    return NativeMappings.pcap_lib_version();
  }

  /**
   * @param inetAddr Inet4Address or Inet6Address
   * @return a string representation of an InetAddress for BPF.
   */
  public static String toBpfString(InetAddress inetAddr) {
    if (inetAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("inetAddr: ").append(inetAddr);
      throw new NullPointerException(sb.toString());
    }

    String strAddr = inetAddr.toString();
    return strAddr.substring(strAddr.lastIndexOf("/") + 1);
  }

  /**
   * @param macAddr macAddr
   * @return a string representation of a MAC address for BPF.
   */
  public static String toBpfString(MacAddress macAddr) {
    if (macAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("macAddr: ").append(macAddr);
      throw new NullPointerException(sb.toString());
    }

    StringBuilder builder = new StringBuilder();
    byte[] address = macAddr.getAddress();

    for (int i = 0; i < address.length; i++) {
      builder.append(String.format("%02x", address[i]));
      builder.append(":");
    }
    builder.deleteCharAt(builder.length() - 1);

    return builder.toString();
  }
}
