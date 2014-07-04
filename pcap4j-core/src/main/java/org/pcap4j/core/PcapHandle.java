/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.core.NativeMappings.pcap_stat;
import org.pcap4j.core.NativeMappings.win_pcap_stat;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * A wrapping class for struct pcap_t.
 * On some OSes, such as Linux and Solaris, this class can't capture packets
 * whose source and destination interface are the same.
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapHandle {

  private static final Logger logger = LoggerFactory.getLogger(PcapHandle.class);

  private volatile DataLinkType dlt;
  private final Pointer handle;
  private final Object thisLock = new Object();
  private final ThreadLocal<Long> timestampsInts
    = new ThreadLocal<Long>();
  private final ThreadLocal<Integer> timestampsMicros
    = new ThreadLocal<Integer>();

  private volatile boolean open = true;
  private volatile String filteringExpression = "";

  private static final Inet4Address WILDCARD_MASK;

  static {
    try {
      WILDCARD_MASK = (Inet4Address)InetAddress.getByName("0.0.0.0");
    } catch (UnknownHostException e) {
      throw new AssertionError("never get here");
    }
  }

  PcapHandle(Pointer handle) {
    this.handle = handle;
    this.dlt = getDltByNative();
  }

  private PcapHandle(Builder builder) throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();
    this.handle
      = NativeMappings.pcap_create(
          builder.deviceName,
          errbuf
        );
    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    if (builder.isSnaplenSet) {
      int rc = NativeMappings.pcap_set_snaplen(handle, builder.snaplen);
      if (rc != 0) {
        throw new PcapNativeException(getError(), rc);
      }
    }
    if (builder.promiscuousMode != null) {
      int rc = NativeMappings.pcap_set_promisc(handle, builder.promiscuousMode.getValue());
      if (rc != 0) {
        throw new PcapNativeException(getError(), rc);
      }
    }
    if (builder.isRfmonSet) {
      try {
        int rc = PcapLibrary.INSTANCE.pcap_set_rfmon(handle, builder.rfmon ? 1 : 0);
        if (rc != 0) {
          throw new PcapNativeException(getError(), rc);
        }
      } catch (UnsatisfiedLinkError e) {
        logger.error("Failed to instantiate PcapHandle object.", e);
        throw new PcapNativeException("Monitor mode is not supported on this platform.");
      }
    }
    if (builder.isTimeoutMillisSet) {
      int rc = NativeMappings.pcap_set_timeout(handle, builder.timeoutMillis);
      if (rc != 0) {
        throw new PcapNativeException(getError(), rc);
      }
    }
    if (builder.isBufferSizeSet) {
      int rc = NativeMappings.pcap_set_buffer_size(handle, builder.bufferSize);
      if (rc != 0) {
        throw new PcapNativeException(getError(), rc);
      }
    }

    int rc = NativeMappings.pcap_activate(handle);
    if (rc < 0) {
      throw new PcapNativeException(getError(), rc);
    }

    this.dlt = getDltByNative();
  }

  DataLinkType getDltByNative() {
    return DataLinkType.getInstance(
             NativeMappings.pcap_datalink(handle)
           );
  }

  /**
   *
   * @return the Data Link Type of this PcapHandle
   */
  public DataLinkType getDlt() { return dlt; }

  /**
   * @param dlt a {@link org.pcap4j.packet.namednumber.DataLinkType DataLinkType}
   *        object to set
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public void setDlt(DataLinkType dlt) throws PcapNativeException, NotOpenException {
    if (dlt == null) {
      throw new NullPointerException("dlt must not be null.");
    }

    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_set_datalink(handle, dlt.value());
      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }

      this.dlt = dlt;
    }
  }

  /**
   *
   * @return true if this PcapHandle object is open (i.e. not yet closed by {@link #close() close()});
   *         false otherwise.
   */
  public boolean isOpen() { return open; }

  /**
   *
   * @return the filtering expression of this PcapHandle
   */
  public String getFilteringExpression() {return filteringExpression; }

  /**
   *
   * @return an integer part of a timestamp of a packet captured in a current thread.
   */
  public Long getTimestampInts() { return timestampsInts.get(); }

  /**
   *
   * @return a fraction part of a timestamp of a packet captured in a current thread.
   *         The value represents the number of microseconds.
   */
  public Integer getTimestampMicros() { return timestampsMicros.get(); }

  /**
   *
   * @return the dimension of the packet portion (in bytes) that is delivered to the application.
   * @throws NotOpenException
   */
  public int getSnapshot() throws NotOpenException {
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      return NativeMappings.pcap_snapshot(handle);
    }
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.16
   */
  public static enum SwappedType {

    /**
     *
     */
    NOT_SWAPPED(0),

    /**
     *
     */
    SWAPPED(1),

    /**
     *
     */
    MAYBE_SWAPPED(2);

    private final int value;

    private SwappedType(int value) {
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
   * @return a {@link org.pcap4j.core.PcapHandle.SwappedType SwappedType} object.
   * @throws NotOpenException
   */
  public SwappedType isSwapped() throws NotOpenException {
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_is_swapped(handle);
      switch (rc) {
        case 0:
          return SwappedType.NOT_SWAPPED;
        case 1:
          return SwappedType.SWAPPED;
        case 2:
          return SwappedType.MAYBE_SWAPPED;
        default:
          logger.warn("pcap_snapshot returned an unexpected code: " + rc);
          return SwappedType.MAYBE_SWAPPED;
      }
    }
  }

  /**
   *
   * @return the major version number of the pcap library used to write the savefile.
   * @throws NotOpenException
   */
  public int getMajorVersion() throws NotOpenException {
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      return NativeMappings.pcap_major_version(handle);
    }
  }

  /**
   *
   * @return the minor version number of the pcap library used to write the savefile.
   * @throws NotOpenException
   */
  public int getMinorVersion() throws NotOpenException {
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      return NativeMappings.pcap_minor_version(handle);
    }
  }

  /**
   *
   * @param bpfExpression
   * @param mode
   * @param netmask
   * @return a {@link org.pcap4j.core.BpfProgram BpfProgram} object.
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public BpfProgram compileFilter(
    String bpfExpression, BpfCompileMode mode, Inet4Address netmask
  ) throws PcapNativeException, NotOpenException {
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

    bpf_program prog = new bpf_program();
    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      rc = NativeMappings.pcap_compile(
             handle, prog, bpfExpression, mode.getValue(),
             ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0)
           );
    }

    if (rc < 0) {
      throw new PcapNativeException(getError(), rc);
    }

    return new BpfProgram(prog, bpfExpression);
  }

  /**
   *
   * @param bpfExpression
   * @param mode
   * @param netmask
   * @throws PcapNativeException
   * @throws NotOpenException
   * @throws NullPointerException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode, Inet4Address netmask
  ) throws PcapNativeException, NotOpenException {
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
      if (!open) {
        throw new NotOpenException();
      }

      int mask = ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0);

      bpf_program prog = new bpf_program();
      try {
        int rc = NativeMappings.pcap_compile(
                   handle, prog, bpfExpression, mode.getValue(), mask
                 );
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_compile: " + getError(),
                      rc
                    );
        }

        rc = NativeMappings.pcap_setfilter(handle, prog);
        if (rc < 0) {
          throw new PcapNativeException(
                      "Error occured in pcap_setfilger: " + getError(),
                      rc
                    );
        }

        this.filteringExpression = bpfExpression;
      } finally {
        NativeMappings.pcap_freecode(prog);
      }
    }
  }

  /**
   *
   * @param bpfExpression
   * @param mode
   * @throws PcapNativeException
   * @throws NotOpenException
   * @throws NullPointerException
   */
  public void setFilter(
    String bpfExpression, BpfCompileMode mode
  ) throws PcapNativeException, NotOpenException {
    setFilter(bpfExpression, mode, WILDCARD_MASK);
  }

  /**
   *
   * @param prog
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public void setFilter(
    BpfProgram prog
  ) throws PcapNativeException, NotOpenException {
    if (prog == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("prog: ").append(prog);
      throw new NullPointerException(sb.toString());
    }

    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_setfilter(handle, prog.getProgram());
      if (rc < 0) {
        throw new PcapNativeException("Failed to set filter: " + getError(), rc);
      }

      this.filteringExpression = prog.getExpression();
    }
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.15
   */
  public static enum BlockingMode {

    /**
     *
     */
    BLOCKING(0),

    /**
     *
     */
    NONBLOCKING(1);

    private final int value;

    private BlockingMode(int value) {
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
   * @param mode
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public void setBlockingMode(
    BlockingMode mode
  ) throws PcapNativeException, NotOpenException {
    if (mode == null) {
      StringBuilder sb = new StringBuilder();
      sb.append(" mode: ").append(mode);
      throw new NullPointerException(sb.toString());
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_setnonblock(handle, mode.getValue(), errbuf);
    }

    if (rc < 0) {
      throw new PcapNativeException(errbuf.toString(), rc);
    }
  }

  /**
   *
   * @return blocking mode
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public BlockingMode getBlockingMode() throws PcapNativeException, NotOpenException {
    PcapErrbuf errbuf = new PcapErrbuf();
    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_getnonblock(handle, errbuf);
    }

    if (rc == 0) {
      return BlockingMode.BLOCKING;
    }
    else if (rc > 0) {
      return BlockingMode.NONBLOCKING;
    }
    else {
      throw new PcapNativeException(errbuf.toString(), rc);
    }
  }

  /**
   *
   * @return a captured packet.
   * @throws NotOpenException
   */
  public Packet getNextPacket() throws NotOpenException {
    pcap_pkthdr header = new pcap_pkthdr();
    Pointer packet;

    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
      packet = NativeMappings.pcap_next(handle, header);
    }

    if (packet != null) {
      timestampsInts.set(header.ts.tv_sec.longValue());
      timestampsMicros.set(header.ts.tv_usec.intValue());

      return PacketFactories.getFactory(Packet.class, DataLinkType.class)
               .newInstance(
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
   * @return a captured packet.
   * @throws PcapNativeException
   * @throws EOFException
   * @throws TimeoutException
   * @throws NotOpenException
   */
  public Packet getNextPacketEx()
  throws PcapNativeException, EOFException, TimeoutException, NotOpenException {
    PointerByReference headerPP = new PointerByReference();
    PointerByReference dataPP = new PointerByReference();
    int rc;

    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
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

        return PacketFactories.getFactory(Packet.class, DataLinkType.class)
                 .newInstance(
                    dataP.getByteArray(0, header.caplen),
                    dlt
                  );
      case -1:
        throw new PcapNativeException(
                "Error occured in pcap_next_ex(): " + getError(), rc
              );
      case -2:
        throw new EOFException();
      default:
        throw new PcapNativeException(
                "Unexpected error occured: " + getError(), rc
              );
    }
  }

  /**
   * A wrapper method for "int pcap_loop(pcap_t *, int, pcap_handler, u_char *)".
   * Once a packet is captured, listener.gotPacket(Packet) is called in the same thread,
   * and this won't capture any other packets until the thread finishes.
   *
   * @param packetCount
   * @param listener
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws NotOpenException
   */
  public void loop(
    int packetCount, PacketListener listener
  ) throws PcapNativeException, InterruptedException, NotOpenException {
    loop(
      packetCount,
      listener,
      SimpleExecutor.getInstance()
    );
  }

  /**
   * A wrapper method for "int pcap_loop(pcap_t *, int, pcap_handler, u_char *)".
   * Once a packet is captured, listener.gotPacket(Packet) is called via the executor.
   * If listener.gotPacket(Packet) is expected to take a long time,
   * this method should be used with proper executor instead of loop(int, PacketListener).
   *
   * @param packetCount
   * @param listener
   * @param executor
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws NotOpenException
   */
  public void loop(
    int packetCount, PacketListener listener, Executor executor
  ) throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener)
        .append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }

    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Start loop");
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
                "Error occured: " + getError(), rc
              );
      case -2:
        logger.info("Broken.");
        throw new InterruptedException();
      default:
        throw new PcapNativeException(
                "Unexpected error occured: " + getError(), rc
              );
    }
  }

  /**
   *
   * @param packetCount
   * @param listener
   * @return the number of captured packets.
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws NotOpenException
   */
  public int dispatch(
    int packetCount, PacketListener listener
  ) throws PcapNativeException, InterruptedException, NotOpenException {
    return dispatch(
             packetCount,
             listener,
             SimpleExecutor.getInstance()
           );
  }

  /**
   *
   * @param packetCount
   * @param listener
   * @param executor
   * @return the number of captured packets.
   * @throws PcapNativeException
   * @throws InterruptedException
   * @throws NotOpenException
   */
  public int dispatch(
    int packetCount, PacketListener listener, Executor executor
  ) throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener)
        .append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }

    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Start dispatch");
      rc = NativeMappings.pcap_dispatch(
             handle,
             packetCount,
             new GotPacketFuncExecutor(listener, dlt, executor),
             null
           );

    }

    if (rc < 0) {
      switch (rc) {
        case -1:
          throw new PcapNativeException(
                  "Error occured: " + getError(),
                  rc
                );
        case -2:
          logger.info("Broken.");
          throw new InterruptedException();
        default:
          throw new PcapNativeException(
                  "Unexpected error occured: " + getError(),
                  rc
                );
      }
    }

    logger.info("Finish dispatch.");
    return rc;
  }

  private static final class SimpleExecutor implements Executor {

    private SimpleExecutor() {}

    private static final SimpleExecutor INSTANCE = new SimpleExecutor();

    public static SimpleExecutor getInstance() { return INSTANCE; }

    @Override
    public void execute(Runnable command) {
      command.run();
    }

  }

  private final class GotPacketFuncExecutor
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

    @Override
    public void got_packet(
      Pointer args, final pcap_pkthdr header, final Pointer packet
    ) {
      final long tvs = header.ts.tv_sec.longValue();
      final int tvus = header.ts.tv_usec.intValue();
      final byte[] ba = packet.getByteArray(0, header.caplen);

      executor.execute(
        new Runnable() {
          @Override
          public void run() {
            timestampsInts.set(tvs);
            timestampsMicros.set(tvus);
            listener.gotPacket(
              PacketFactories.getFactory(Packet.class, DataLinkType.class)
                .newInstance(
                   ba,
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
   * @return an opened PcapDumper.
   * @throws PcapNativeException
   */
  public PcapDumper dumpOpen(String filePath) throws PcapNativeException {
    if (filePath == null) {
      throw new NullPointerException("filePath must not be null.");
    }

    Pointer dumper;
    synchronized (thisLock) {
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
   * @throws NotOpenException
   */
  public
  void loop(int packetCount, PcapDumper dumper)
  throws PcapNativeException, InterruptedException, NotOpenException {
    if (dumper == null) {
      throw new NullPointerException("dumper must not be null.");
    }

    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Start dump loop");
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
                "Error occured: " + getError(), rc
              );
      case -2:
        logger.info("Broken.");
        throw new InterruptedException();
      default:
        throw new PcapNativeException(
                "Unexpected error occured: " + getError(), rc
              );
    }
  }

  /**
   * Breaks a loop which this handle is working on.
   *
   * The loop may not be broken immediately on some OSes
   * because of buffering or something.
   * As a workaround, letting this capture some bogus packets
   * after calling this method may work.
   */
  public void breakLoop() {
    logger.info("Break loop.");
    NativeMappings.pcap_breakloop(handle);
  }

  /**
   *
   * @param packet
   * @throws PcapNativeException
   * @throws NotOpenException
   * @throws NullPointerException
   */
  public void sendPacket(Packet packet) throws PcapNativeException, NotOpenException {
    if (packet == null) {
      throw new NullPointerException("packet may not be null");
    }

    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_sendpacket(
             handle, packet.getRawData(), packet.length()
           );
    }

    if (rc < 0) {
      throw new PcapNativeException(
              "Error occured in pcap_sendpacket(): " + getError(),
              rc
            );
    }
  }

  /**
   * Closes this PcapHandle.
   */
  public void close() {
    synchronized (thisLock) {
      if (!open) {
        logger.warn("Already closed.");
        return;
      }
      NativeMappings.pcap_close(handle);
      open = false;
    }

    logger.info("Closed.");
  }

  /**
   *
   * @return a {@link org.pcap4j.core.PcapStat PcapStat} object.
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public PcapStat getStats() throws PcapNativeException, NotOpenException {
    if (Platform.isWindows()) {
      Pointer psp;
      IntByReference pcapStatSize = new IntByReference();
      synchronized (thisLock) {
        if (!open) {
          throw new NotOpenException();
        }
        psp = PcapLibrary.INSTANCE.win_pcap_stats_ex(handle, pcapStatSize);
      }

      if (pcapStatSize.getValue() != 24) {
        throw new PcapNativeException(getError());
      }
      if (psp == null) {
        throw new PcapNativeException(getError());
      }

      return new PcapStat(new win_pcap_stat(psp));
    }
    else {
      pcap_stat ps = new pcap_stat();
      int rc;
      synchronized (thisLock) {
        if (!open) {
          throw new NotOpenException();
        }
        rc = NativeMappings.pcap_stats(handle, ps);
      }

      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }

      return new PcapStat(ps);
    }


  }

//  /**
//   *
//   * @return a {@link org.pcap4j.core.PcapStatEx PcapStatEx} object.
//   * @throws PcapNativeException
//   * @throws NotOpenException
//   */
//  public PcapStatEx getStatsEx() throws PcapNativeException, NotOpenException {
//    if (!Platform.isWindows()) {
//      throw new UnsupportedOperationException("This method is only for Windows.");
//    }
//
//    pcap_stat_ex ps = new pcap_stat_ex();
//    int rc = PcapLibrary.INSTANCE.dos_pcap_stats_ex(handle, ps);
//    if (rc < 0) {
//      throw new PcapNativeException(getError(), rc);
//    }
//
//    return new PcapStatEx(ps);
//  }

  /**
   * @return a list of {@link org.pcap4j.packet.namednumber.DataLinkType DataLinkType}
   * @throws PcapNativeException
   * @throws NotOpenException
   */
  public List<DataLinkType> listDatalinks()
  throws PcapNativeException, NotOpenException {
    PointerByReference dltBufPP = new PointerByReference();
    int rc;
    synchronized (thisLock) {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_list_datalinks(handle, dltBufPP);
    }

    if (rc < 0) {
      throw new PcapNativeException(getError(), rc);
    }

    Pointer dltBufP = dltBufPP.getValue();
    List<DataLinkType> list = new ArrayList<DataLinkType>(rc);
    for (int i = 0; i < rc; i++) {
      list.add(DataLinkType.getInstance(dltBufP.getInt(Pointer.SIZE * i)));
    }

    NativeMappings.pcap_free_datalinks(dltBufP);
    return list;
  }

  /**
   *
   * @return an error message.
   */
  public String getError() {
    return NativeMappings.pcap_geterr(handle).getString(0);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(60);

    sb.append("Link type: [").append(dlt)
      .append("] handle: [").append(handle)
      .append("] Open: [").append(open)
      .append("] Filtering Expression: [").append(filteringExpression)
      .append("]");

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.2.0
   */
  public static final class Builder {

    private final String deviceName;
    private int snaplen;
    private boolean isSnaplenSet = false;
    private PromiscuousMode promiscuousMode = null;
    private boolean rfmon;
    private boolean isRfmonSet = false;
    private int timeoutMillis;
    private boolean isTimeoutMillisSet = false;
    private int bufferSize;
    private boolean isBufferSizeSet = false;

    /**
     *
     * @param deviceName A value {@link PcapNetworkInterface#getName()} returns.
     */
    public Builder(String deviceName) {
      if (deviceName == null || deviceName.length() == 0) {
        throw new IllegalArgumentException("deviceName: " + deviceName);
      }
      this.deviceName = deviceName;
    }

    /**
     * @param snaplen Snapshot length, which is the number of bytes captured for each packet.
     *                If this method isn't called, the platform's default snaplen will be applied
     *                at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder snaplen(int snaplen) {
      this.snaplen = snaplen;
      this.isSnaplenSet = true;
      return this;
    }

    /**
     * @param promiscuousMode Promiscuous mode.
     *                        If this method isn't called,
     *                        the platform's default mode will be used
     *                        at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder promiscuousMode(PromiscuousMode promiscuousMode) {
      this.promiscuousMode = promiscuousMode;
      return this;
    }

    /**
     * @param rfmon Whether monitor mode should be set on a PcapHandle
     *              when it is built. If true, monitor mode will be set,
     *              otherwise it will not be set.
     *              Some platforms don't support setting monitor mode.
     *              Calling this method on such platforms may cause PcapNativeException
     *              at {@link #build()}.
     *              If this method isn't called, the platform's default mode will be applied
     *              at {@link #build()} (if supported).
     * @return this Builder object for method chaining.
     */
    public Builder rfmon(boolean rfmon) {
      this.rfmon = rfmon;
      this.isRfmonSet = true;
      return this;
    }

    /**
     * @param timeoutMillis Read timeout. Most OSs buffer packets.
     *                      The OSs pass the packets to Pcap4j after the buffer gets full
     *                      or the read timeout expires.
     *                      Must be non-negative. May be ignored by some OSs.
     *                      0 means disable buffering on Solaris.
     *                      0 means infinite on the other OSs.
     *                      1 through 9 means infinite on Solaris.
     *                      If this method isn't called, the platform's default timeout will be applied
     *                      at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder timeoutMillis(int timeoutMillis) {
      this.timeoutMillis = timeoutMillis;
      this.isTimeoutMillisSet = true;
      return this;
    }

    /**
     * @param bufferSize The buffer size, which is in units of bytes.
     *                   If this method isn't called,
     *                   the platform's default buffer size will be applied
     *                   at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder bufferSize(int bufferSize) {
      this.bufferSize = bufferSize;
      this.isBufferSizeSet = true;
      return this;
    }

    /**
     * @return a new PcapHandle object.
     * @throws PcapNativeException
     */
    public PcapHandle build() throws PcapNativeException {
      return new PcapHandle(this);
    }

  }

}
