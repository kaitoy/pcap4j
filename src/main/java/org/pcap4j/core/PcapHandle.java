/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;
import org.apache.log4j.Logger;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PacketFactory;
import org.pcap4j.packet.namedvalue.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BIT;
import static org.pcap4j.util.ByteArrays.IP_ADDRESS_SIZE_IN_BYTE;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapHandle {

  private static final Logger logger = Logger.getLogger(PcapHandle.class);

  private final DataLinkType dlt;
  private final Pointer handle;

  private boolean opening;
  private String filteringExpression = "";

  /**
   *
   * @param handle
   */
  public PcapHandle(Pointer handle) {
    this.dlt = DataLinkType.getInstance(
                 PcapLibrary.INSTANCE.pcap_datalink(handle)
               );
    this.handle = handle;
    this.opening = true;
  }

  /**
   *
   * @return
   */
  public boolean isOpening() {
    return opening;
  }

  /**
   *
   * @return
   */
  public String getFilteringExpression() {
    return filteringExpression;
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public enum BpfCompileMode {
    OPTIMIZE(1),
    NONOPTIMIZE(0);

    private final int value;

    private BpfCompileMode(int value) {
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

  /**
   *
   * @param bpfExpression
   * @param mode
   * @param netmask
   * @throws PcapNativeException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode, InetAddress netmask
  ) throws PcapNativeException {
    if (!isOpening()) {
      throw new IllegalStateException("Not opening.");
    }

    int mask;
    if (netmask != null) {
      byte[] rawNetmask = ByteArrays.toByteArray(netmask);
      if (rawNetmask.length != IP_ADDRESS_SIZE_IN_BYTE) {
        throw new IllegalArgumentException();
      }

      mask =    rawNetmask[3]
             | (rawNetmask[2] << (BYTE_SIZE_IN_BIT * 1))
             | (rawNetmask[1] << (BYTE_SIZE_IN_BIT * 2))
             | (rawNetmask[0] << (BYTE_SIZE_IN_BIT * 3));
    }
    else {
      mask = 0;
    }

    bpf_program prog = new bpf_program();
    int rc = PcapLibrary.INSTANCE.pcap_compile(
               handle, prog, bpfExpression, mode.getValue(), mask
             );
    if (rc < 0) {
      throw new PcapNativeException("Error occured in pcap_compile: " + getError());
    }

    rc = PcapLibrary.INSTANCE.pcap_setfilter(handle, prog);
    if (rc < 0) {
      throw new PcapNativeException("Error occured in pcap_setfilger: " + getError());
    }

    this.filteringExpression = bpfExpression;
    PcapLibrary.INSTANCE.pcap_freecode(prog);
  }

  /**
   *
   * @return
   */
  public Packet getNextPacket() {
    if (!isOpening()) {
      throw new IllegalStateException("Not opening.");
    }

    pcap_pkthdr header = new pcap_pkthdr();
    Pointer packet = PcapLibrary.INSTANCE.pcap_next(handle, header);

    if (packet != null) {
      return PacketFactory.getInstance().newPacketByDlt(
               packet.getByteArray(0, header.caplen), dlt.value()
             );
    }
    else {
      return null;
    }
  }

  /**
   *
   * @return
   * @throws PcapNativeException
   */
  public Packet getNextPacketEx() throws PcapNativeException {
    if (!isOpening()) {
      throw new IllegalStateException("Not opening.");
    }

    PointerByReference headerPP = new PointerByReference();
    PointerByReference dataPP = new PointerByReference();

    int rc = PcapLibrary.INSTANCE.pcap_next_ex(handle, headerPP, dataPP);

    switch (rc) {
      case 0:
        logger.debug("Timeout expired. Got no packet.");
        return null;

      case 1:
        Pointer headerP = headerPP.getValue();
        Pointer dataP = dataPP.getValue();
        if (headerP == null || dataP == null) {
          throw new AssertionError("Never get here.");
        }

        return PacketFactory.getInstance().newPacketByDlt(
                 dataP.getByteArray(0, new pcap_pkthdr(headerP).caplen),
                 dlt.value()
               );

      case -1:
        throw new PcapNativeException(
                "Error occured in pcap_next_ex(): " + getError()
              );

      case -2:
        logger.info("Got EOF.");
        return null;

      default:
        throw new AssertionError("Never get here.");
    }
  }

  /**
   *
   * @param packetCount
   * @param eventListener
   * @throws PcapNativeException
   */
  public void loop(
    int packetCount, GotPacketEventListener eventListener
  ) throws PcapNativeException {
    if (!isOpening()) {
      throw new IllegalStateException("Not opening.");
    }

    class gotPacketFunc implements NativeMappings.pcap_handler {
      private final GotPacketEventListener eventListener;

      public gotPacketFunc(GotPacketEventListener eventListener) {
        this.eventListener = eventListener;
      }

      public void got_packet(String args, pcap_pkthdr header, Pointer packet) {
        eventListener.gotPacket(
          PacketFactory.getInstance().newPacketByDlt(
            packet.getByteArray(0, header.caplen),
            dlt.value()
          )
        );
      }
    }

    logger.info("Start loop");
    int rc = PcapLibrary.INSTANCE.pcap_loop(
               handle,
               packetCount,
               new gotPacketFunc(eventListener),
               ""
             );

    switch (rc) {
      case  0: logger.info("Finish loop."); break;
      case -1: throw new PcapNativeException("Error occured in pcap_loop(): " + getError());
      case -2: logger.info("Breaked."); break;
      default: throw new AssertionError();
    }
  }

  /**
   *
   */
  public void breakLoop() {
    if (!isOpening()) {
      throw new IllegalStateException("Not opening.");
    }

    PcapLibrary.INSTANCE.pcap_breakloop(handle);
  }

  /**
   *
   * @param packet
   * @throws PcapNativeException
   */
  public void sendPacket(Packet packet) throws PcapNativeException {
    int rc = PcapLibrary.INSTANCE.pcap_sendpacket(
               handle, packet.getRawData(), packet.length()
             );


    if (rc < 0) {
      throw new PcapNativeException("Error occured in pcap_sendpacket(): " + getError());
    }
  }

  /**
   *
   */
  public void close() {
    if (!isOpening()) {
      logger.warn("Already closed.");
      return;
    }

    PcapLibrary.INSTANCE.pcap_close(handle);
    opening = false;
    logger.info("Closed.");
  }

  /**
   *
   * @return
   */
  public String getError() {
    return PcapLibrary.INSTANCE.pcap_geterr(handle).getString(0);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("Link type: [").append(dlt)
      .append("] handle: [").append(handle)
      .append("] Opening: [").append(opening)
      .append("]");

    return sb.toString();
  }

//  @Override
//  public boolean equals(Object obj) {}
//  @Override
//  public int hashCode() {}

}
