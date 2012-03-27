/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.io.EOFException;
import java.net.InetAddress;
import java.util.concurrent.Executor;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapHandle {

  private static final Logger logger = LoggerFactory.getLogger(PcapHandle.class);

  private final DataLinkType dlt;
  private final Pointer handle;
  private final Object thisLock = new Object();

  private volatile boolean opening;
  private volatile String filteringExpression = "";

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
  public static enum BpfCompileMode {
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
   * @param bpfExpression
   * @param mode
   * @param netmask
   * @throws PcapNativeException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode, InetAddress netmask
  ) throws PcapNativeException {
    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      int mask;
      if (netmask != null) {
        mask = ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0);
      }
      else {
        mask = 0;
      }

      bpf_program prog = new bpf_program();
      try {
        int rc = PcapLibrary.INSTANCE.pcap_compile(
                   handle, prog, bpfExpression, mode.getValue(), mask
                 );
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_compile: " + getError()
                    );
        }

        rc = PcapLibrary.INSTANCE.pcap_setfilter(handle, prog);
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_setfilger: " + getError()
                    );
        }

        this.filteringExpression = bpfExpression;
      } finally {
        PcapLibrary.INSTANCE.pcap_freecode(prog);
      }
    }
  }

  /**
   *
   * @return
   */
  public Packet getNextPacket() {
    pcap_pkthdr header = new pcap_pkthdr();
    Pointer packet;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      header = new pcap_pkthdr();
      packet = PcapLibrary.INSTANCE.pcap_next(handle, header);
    }

    if (packet != null) {
      return PacketFactories.getPacketFactory(DataLinkType.class).newPacket(
               packet.getByteArray(0, header.caplen),
               dlt
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
   * @throws EOFException
   */
  public Packet getNextPacketEx() throws PcapNativeException, EOFException {
    PointerByReference headerPP = new PointerByReference();
    PointerByReference dataPP = new PointerByReference();
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
      rc = PcapLibrary.INSTANCE.pcap_next_ex(handle, headerPP, dataPP);
    }

    switch (rc) {
      case 0:
        logger.debug("timeout");
        return null;
      case 1:
        Pointer headerP = headerPP.getValue();
        Pointer dataP = dataPP.getValue();
        if (headerP == null || dataP == null) {
          throw new PcapNativeException(
                      "Failed to get packet. *header: "
                        + headerP + " *data: " + dataP
                    );
        }

        return PacketFactories.getPacketFactory(DataLinkType.class).newPacket(
                 dataP.getByteArray(0, new pcap_pkthdr(headerP).caplen),
                 dlt
               );
      case -1:
        throw new PcapNativeException(
                "Error occured in pcap_next_ex(): " + getError()
              );
      case -2:
        throw new EOFException();
      default:
        throw new AssertionError("Never get here.");
    }
  }

  /**
   *
   * @param packetCount
   * @param listener
   * @throws PcapNativeException
   */
  public void loop(
    int packetCount, PacketListener listener
  ) throws PcapNativeException {
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      logger.info("Start loop");
      rc = PcapLibrary.INSTANCE.pcap_loop(
             handle,
             packetCount,
             new gotPacketFunc(listener, dlt),
             ""
           );
    }

    switch (rc) {
      case  0: logger.info("Finish loop."); break;
      case -1: throw new PcapNativeException(
                       "Error occured: " + getError()
                     );
      case -2: logger.info("Broken."); break;
      default: throw new AssertionError();
    }
  }

  private static class gotPacketFunc implements NativeMappings.pcap_handler {

    private final DataLinkType dlt;
    private final PacketListener listener;

    public gotPacketFunc(PacketListener listener, DataLinkType dlt) {
      this.dlt = dlt;
      this.listener = listener;
    }

    public void got_packet(String args, pcap_pkthdr header, Pointer packet) {
      listener.gotPacket(
        PacketFactories.getPacketFactory(DataLinkType.class).newPacket(
          packet.getByteArray(0, header.caplen),
          dlt
        )
      );
    }

  }

  public void loop(
    int packetCount, PacketListener listener, Executor executor
  ) throws PcapNativeException {
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      logger.info("Start loop");
      rc = PcapLibrary.INSTANCE.pcap_loop(
             handle,
             packetCount,
             new gotPacketFuncExecutor(listener, dlt, executor),
             ""
           );
    }

    switch (rc) {
      case  0: logger.info("Finish loop."); break;
      case -1: throw new PcapNativeException(
                       "Error occured: " + getError()
                     );
      case -2: logger.info("Broken."); break;
      default: throw new AssertionError();
    }
  }

  private static class gotPacketFuncExecutor
  implements NativeMappings.pcap_handler {

    private final DataLinkType dlt;
    private final PacketListener listener;
    private final Executor executor;

    public gotPacketFuncExecutor(
      PacketListener listener, DataLinkType dlt, Executor executor
    ) {
      this.dlt = dlt;
      this.listener = listener;
      this.executor = executor;
    }

    public void got_packet(
      String args, final pcap_pkthdr header, final Pointer packet
    ) {
      executor.execute(
        new Runnable() {
          public void run() {
            listener.gotPacket(
              PacketFactories.getPacketFactory(DataLinkType.class).newPacket(
                packet.getByteArray(0, header.caplen),
                dlt
              )
            );
          }
        }
      );
    }

  }

  /**
   *
   */
  public void breakLoop() {
//    if (!opening) {  // not need to check
//      throw new IllegalStateException("Not opening.");
//    }
    logger.info("Break loop.");
    PcapLibrary.INSTANCE.pcap_breakloop(handle);
  }

  /**
   *
   * @param packet
   * @throws PcapNativeException
   */
  public void sendPacket(Packet packet) throws PcapNativeException {
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
      rc = PcapLibrary.INSTANCE.pcap_sendpacket(
             handle, packet.getRawData(), packet.length()
           );
    }

    if (rc < 0) {
      throw new PcapNativeException(
              "Error occured in pcap_sendpacket(): " + getError()
            );
    }
  }

  /**
   *
   */
  public void close() {
    synchronized (thisLock) {
      if (!opening) {
        logger.warn("Already closed.");
        return;
      }
      PcapLibrary.INSTANCE.pcap_close(handle);
      opening = false;
    }

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
    StringBuilder sb = new StringBuilder(60);

    sb.append("Link type: [").append(dlt)
      .append("] handle: [").append(handle)
      .append("] Opening: [").append(opening)
      .append("]");

    return sb.toString();
  }

}
