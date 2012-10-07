/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
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
  private final ThreadLocal<Long> timestampsInts
    = new ThreadLocal<Long>();
  private final ThreadLocal<Integer> timestampsMicros
    = new ThreadLocal<Integer>();

  private volatile boolean opening;
  private volatile String filteringExpression = "";

  private static final Inet4Address WILDCARD_MASK;

  static {
    try {
      WILDCARD_MASK = (Inet4Address)InetAddress.getByName("0.0.0.0");
    } catch (UnknownHostException e) {
      throw new AssertionError("never get here");
    }
  }

  PcapHandle(Pointer handle, boolean opening) {
//    this.dlt = DataLinkType.getInstance(
//                 PcapLibrary.INSTANCE.pcap_datalink(handle)
//               );
    this.dlt = DataLinkType.getInstance(
                 NativeMappings.pcap_datalink(handle)
               );
    this.handle = handle;
    this.opening = opening;
  }

  /**
   *
   * @return
   */
  public DataLinkType getDlt() { return dlt; }

  /**
   *
   * @return
   */
  public boolean isOpening() { return opening; }

  /**
   *
   * @return
   */
  public String getFilteringExpression() {return filteringExpression; }

  /**
   *
   * @return
   */
  public Long getTimestampInts() { return timestampsInts.get(); }

  /**
   *
   * @return
   */
  public Integer getTimestampMicros() { return timestampsMicros.get(); }

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
   * @throws IllegalStateException
   * @throws NullPointerException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode, Inet4Address netmask
  ) throws PcapNativeException {
    if (
         bpfExpression == null
      || mode == null
      || netmask == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("bpfExpression: ").append(bpfExpression)
        .append(" mode: ").append(mode)
        .append(" netmask: ").append(netmask);
      throw new NullPointerException(sb.toString());
    }

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      int mask = ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0);

      bpf_program prog = new bpf_program();
      try {
//        int rc = PcapLibrary.INSTANCE.pcap_compile(
//                   handle, prog, bpfExpression, mode.getValue(), mask
//                 );
        int rc = NativeMappings.pcap_compile(
                   handle, prog, bpfExpression, mode.getValue(), mask
                 );
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_compile: " + getError()
                    );
        }

        // rc = PcapLibrary.INSTANCE.pcap_setfilter(handle, prog);
        rc = NativeMappings.pcap_setfilter(handle, prog);
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_setfilger: " + getError()
                    );
        }

        this.filteringExpression = bpfExpression;
      } finally {
        // PcapLibrary.INSTANCE.pcap_freecode(prog);
        NativeMappings.pcap_freecode(prog);
      }
    }
  }

  /**
   *
   * @param bpfExpression
   * @param mode
   * @throws PcapNativeException
   * @throws IllegalStateException
   * @throws NullPointerException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode
  ) throws PcapNativeException {
    setFilter(bpfExpression, mode, WILDCARD_MASK);
  }

  /**
   *
   * @return
   * @throws IllegalStateException
   */
  public Packet getNextPacket() {
    pcap_pkthdr header = new pcap_pkthdr();
    Pointer packet;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
      // packet = PcapLibrary.INSTANCE.pcap_next(handle, header);
      packet = NativeMappings.pcap_next(handle, header);
    }

    if (packet != null) {
      timestampsInts.set(header.ts.tv_sec.longValue());
      timestampsMicros.set(header.ts.tv_usec.intValue());

      return PacketFactories.getFactory(DataLinkType.class)
               .newPacket(
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
   * @throws TimeoutException
   * @throws IllegalStateException
   */
  public Packet getNextPacketEx()
  throws PcapNativeException, EOFException, TimeoutException {
    PointerByReference headerPP = new PointerByReference();
    PointerByReference dataPP = new PointerByReference();
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
      // rc = PcapLibrary.INSTANCE.pcap_next_ex(handle, headerPP, dataPP);
      rc = NativeMappings.pcap_next_ex(handle, headerPP, dataPP);
    }

    switch (rc) {
      case 0:
        throw new TimeoutException();
      case 1:
        Pointer headerP = headerPP.getValue();
        Pointer dataP = dataPP.getValue();
        if (headerP == null || dataP == null) {
          throw new PcapNativeException(
                      "Failed to get packet. *header: "
                        + headerP + " *data: " + dataP
                    );
        }

        pcap_pkthdr header = new pcap_pkthdr(headerP);
        timestampsInts.set(header.ts.tv_sec.longValue());
        timestampsMicros.set(header.ts.tv_usec.intValue());

        return PacketFactories.getFactory(DataLinkType.class)
                 .newPacket(
                    dataP.getByteArray(0, header.caplen),
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
   * @throws InterruptedException
   * @throws IllegalStateException
   */
  public void loop(
    int packetCount, PacketListener listener
  ) throws PcapNativeException, InterruptedException {
    loop(
      packetCount,
      listener,
      new Executor() {
        public void execute(Runnable command) {
          command.run();
        }
      }
    );
  }

  /**
   *
   * @param packetCount
   * @param listener
   * @param executor
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws IllegalStateException
   */
  public void loop(
    int packetCount, PacketListener listener, Executor executor
  ) throws PcapNativeException, InterruptedException {
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      logger.info("Start loop");
//      rc = PcapLibrary.INSTANCE.pcap_loop(
//             handle,
//             packetCount,
//             new GotPacketFuncExecutor(listener, dlt, executor),
//             null
//           );
      rc = NativeMappings.pcap_loop(
             handle,
             packetCount,
             new GotPacketFuncExecutor(listener, dlt, executor),
             null
           );
    }

    switch (rc) {
      case  0:
        logger.info("Finish loop.");
        break;
      case -1:
        throw new PcapNativeException(
                "Error occured: " + getError()
              );
      case -2:
        logger.info("Broken.");
        throw new InterruptedException();
      default:
        throw new PcapNativeException(
                "Unexpected error occured: " + getError()
              );
    }
  }

  private class GotPacketFuncExecutor
  implements NativeMappings.pcap_handler {

    private final DataLinkType dlt;
    private final PacketListener listener;
    private final Executor executor;

    public GotPacketFuncExecutor(
      PacketListener listener, DataLinkType dlt, Executor executor
    ) {
      this.dlt = dlt;
      this.listener = listener;
      this.executor = executor;
    }

    public void got_packet(
      Pointer args, final pcap_pkthdr header, final Pointer packet
    ) {
      executor.execute(
        new Runnable() {
          public void run() {
            timestampsInts.set(header.ts.tv_sec.longValue());
            timestampsMicros.set(header.ts.tv_usec.intValue());

            listener.gotPacket(
              PacketFactories.getFactory(DataLinkType.class)
                .newPacket(
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
   * @param filePath "-" means stdout.
   *        The dlt of the PcapHandle which captured the packets you want to dump
   *        must be the same as this dlt.
   * @return
   * @throws PcapNativeException
   */
  public PcapDumper dumpOpen(String filePath) throws PcapNativeException {
    Pointer dumper;

    synchronized (thisLock) {
      // dumper = PcapLibrary.INSTANCE.pcap_dump_open(handle, filePath);
      dumper = NativeMappings.pcap_dump_open(handle, filePath);
      if (dumper == null) {
        throw new PcapNativeException(getError());
      }
    }

    return new PcapDumper(dumper);
  }

  /**
   *
   * @param packetCount
   * @param dumper
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws IllegalStateException
   */
  public
  void loop(int packetCount, PcapDumper dumper)
  throws PcapNativeException, InterruptedException {
    int rc;

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }

      logger.info("Start dump loop");
//      rc = PcapLibrary.INSTANCE.pcap_loop(
//             handle,
//             packetCount,
//             NativeMappings.PCAP_DUMP,
//             dumper.getDumper()
//           );
      rc = NativeMappings.pcap_loop(
             handle,
             packetCount,
             NativeMappings.PCAP_DUMP,
             dumper.getDumper()
           );
    }

    switch (rc) {
      case  0:
        logger.info("Finish dump loop.");
        break;
      case -1:
        throw new PcapNativeException(
                "Error occured: " + getError()
              );
      case -2:
        logger.info("Broken.");
        throw new InterruptedException();
      default:
        throw new AssertionError("Never get here");
    }
  }

  /**
   *
   */
  public void breakLoop() {
    logger.info("Break loop.");
    // PcapLibrary.INSTANCE.pcap_breakloop(handle);
    NativeMappings.pcap_breakloop(handle);
  }

  /**
   *
   * @param packet
   * @throws PcapNativeException
   * @throws NullPointerException
   * @throws IllegalStateException
   */
  public void sendPacket(Packet packet) throws PcapNativeException {
    if (packet == null) {
      throw new NullPointerException("packet may not be null");
    }

    int rc;
    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
//      rc = PcapLibrary.INSTANCE.pcap_sendpacket(
//             handle, packet.getRawData(), packet.length()
//           );
      rc = NativeMappings.pcap_sendpacket(
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
      // PcapLibrary.INSTANCE.pcap_close(handle);
      NativeMappings.pcap_close(handle);
      opening = false;
    }

    logger.info("Closed.");
  }

  /**
   *
   * @return
   */
  public String getError() {
    // return PcapLibrary.INSTANCE.pcap_geterr(handle).getString(0);
    return NativeMappings.pcap_geterr(handle).getString(0);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(60);

    sb.append("Link type: [").append(dlt)
      .append("] handle: [").append(handle)
      .append("] Opening: [").append(opening)
      .append("] Filtering Expression: [").append(filteringExpression)
      .append("]");

    return sb.toString();
  }

}
