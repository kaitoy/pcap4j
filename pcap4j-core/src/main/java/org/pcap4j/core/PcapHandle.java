/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.io.Closeable;
import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NativeMappings.PcapErrbuf;
import org.pcap4j.core.NativeMappings.PcapLibrary;
import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.core.NativeMappings.pcap_stat;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A wrapper class for struct pcap_t.
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapHandle implements Closeable {

  private static final Logger logger = LoggerFactory.getLogger(PcapHandle.class);

  private volatile DataLinkType dlt;
  private final TimestampPrecision timestampPrecision;
  private final Pointer handle;
  private final ThreadLocal<Timestamp> timestamps = new ThreadLocal<Timestamp>();
  private final ThreadLocal<Integer> originalLengths = new ThreadLocal<Integer>();
  private final ReentrantReadWriteLock handleLock = new ReentrantReadWriteLock(true);
  private static final Object compileLock = new Object();

  private volatile boolean open = true;
  private volatile String filteringExpression = "";

  /**
   * The netmask used for {@link #setFilter(String, BpfProgram.BpfCompileMode, Inet4Address)} or
   * {@link #compileFilter(String, BpfProgram.BpfCompileMode, Inet4Address)} when you don't know
   * what netmask you should use.
   */
  public static final Inet4Address PCAP_NETMASK_UNKNOWN;

  static {
    try {
      PCAP_NETMASK_UNKNOWN = (Inet4Address) InetAddress.getByName("255.255.255.255");
    } catch (UnknownHostException e) {
      throw new AssertionError("never get here");
    }
  }

  PcapHandle(Pointer handle, TimestampPrecision timestampPrecision) {
    this.handle = handle;
    this.dlt = getDltByNative();
    this.timestampPrecision = timestampPrecision;
  }

  private PcapHandle(Builder builder) throws PcapNativeException {
    PcapErrbuf errbuf = new PcapErrbuf();
    this.handle = NativeMappings.pcap_create(builder.deviceName, errbuf);
    if (handle == null || errbuf.length() != 0) {
      throw new PcapNativeException(errbuf.toString());
    }

    try {
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
      if (builder.timestampPrecision != null) {
        try {
          int rc =
              PcapLibrary.INSTANCE.pcap_set_tstamp_precision(
                  handle, builder.timestampPrecision.getValue());
          if (rc == 0) {
            this.timestampPrecision = builder.timestampPrecision;
          } else {
            StringBuilder sb =
                new StringBuilder(100)
                    .append("The specified timestamp precision ")
                    .append(builder.timestampPrecision)
                    .append(" is not supported on this platform. ")
                    .append(TimestampPrecision.MICRO)
                    .append(" is set instead.");

            logger.error(sb.toString());
            this.timestampPrecision = TimestampPrecision.MICRO;
          }
        } catch (UnsatisfiedLinkError e) {
          throw new PcapNativeException(
              "pcap_set_tstamp_precision is not supported by the pcap library"
                  + " installed in this environment.");
        }
      } else {
        this.timestampPrecision = TimestampPrecision.MICRO;
      }
      if (builder.isImmediateModeSet) {
        try {
          int rc =
              PcapLibrary.INSTANCE.pcap_set_immediate_mode(handle, builder.immediateMode ? 1 : 0);
          if (rc != 0) {
            throw new PcapNativeException(getError(), rc);
          }
        } catch (UnsatisfiedLinkError e) {
          logger.error("Failed to instantiate PcapHandle object.", e);
          throw new PcapNativeException("Immediate mode is not supported on this platform.");
        }
      }

      int activateRc = NativeMappings.pcap_activate(handle);
      if (activateRc < 0) {
        throw new PcapNativeException(getError(), activateRc);
      }

      if (builder.direction != null) {
        int rc = NativeMappings.pcap_setdirection(handle, builder.direction.getValue());
        if (rc < 0) {
          throw new PcapNativeException("Failed to set direction: " + getError(), rc);
        }
      }
    } catch (NotOpenException e) {
      throw new AssertionError("Never get here.");
    }

    this.dlt = getDltByNative();
  }

  private DataLinkType getDltByNative() {
    return DataLinkType.getInstance(NativeMappings.pcap_datalink(handle));
  }

  /** @return the Data Link Type of this PcapHandle */
  public DataLinkType getDlt() {
    return dlt;
  }

  /**
   * @param dlt a {@link org.pcap4j.packet.namednumber.DataLinkType DataLinkType} object to set
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void setDlt(DataLinkType dlt) throws PcapNativeException, NotOpenException {
    if (dlt == null) {
      throw new NullPointerException("dlt must not be null.");
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_set_datalink(handle, dlt.value());
      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }

    this.dlt = dlt;
  }

  /**
   * @return true if this PcapHandle object is open (i.e. not yet closed by {@link #close()
   *     close()}); false otherwise.
   */
  public boolean isOpen() {
    return open;
  }

  /** @return the filtering expression of this PcapHandle */
  public String getFilteringExpression() {
    return filteringExpression;
  }

  /** @return Timestamp precision */
  public TimestampPrecision getTimestampPrecision() {
    return timestampPrecision;
  }

  /**
   * Set direction flag, which controls whether we accept only incoming packets, only outgoing
   * packets, or both. Note that, depending on the platform, some or all direction arguments might
   * not be supported.
   *
   * @param direction direction to set.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void setDirection(PcapDirection direction) throws PcapNativeException, NotOpenException {
    if (direction == null) {
      throw new NullPointerException("direction must not be null.");
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_setdirection(handle, direction.getValue());
      if (rc < 0) {
        throw new PcapNativeException("Failed to set direction: " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /** @return the timestamp of the last packet captured by this handle in the current thread. */
  public Timestamp getTimestamp() {
    return timestamps.get();
  }

  /**
   * @return the original length of the last packet captured by this handle in the current thread.
   */
  public Integer getOriginalLength() {
    return originalLengths.get();
  }

  /**
   * @return the dimension of the packet portion (in bytes) that is delivered to the application.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int getSnapshot() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      return NativeMappings.pcap_snapshot(handle);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @return a {@link org.pcap4j.core.PcapHandle.SwappedType SwappedType} object.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public SwappedType isSwapped() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    int rc;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_is_swapped(handle);
    } finally {
      handleLock.readLock().unlock();
    }

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

  /**
   * @return the major version number of the pcap library used to write the savefile.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int getMajorVersion() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      return NativeMappings.pcap_major_version(handle);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @return the minor version number of the pcap library used to write the savefile.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int getMinorVersion() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      return NativeMappings.pcap_minor_version(handle);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @param bpfExpression bpfExpression
   * @param mode mode
   * @param netmask netmask
   * @return a {@link org.pcap4j.core.BpfProgram BpfProgram} object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public BpfProgram compileFilter(String bpfExpression, BpfCompileMode mode, Inet4Address netmask)
      throws PcapNativeException, NotOpenException {
    if (bpfExpression == null || mode == null || netmask == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("bpfExpression: ")
          .append(bpfExpression)
          .append(" mode: ")
          .append(mode)
          .append(" netmask: ")
          .append(netmask);
      throw new NullPointerException(sb.toString());
    }
    if (!open) {
      throw new NotOpenException();
    }

    bpf_program prog;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      prog = new bpf_program();
      int rc;
      synchronized (compileLock) {
        rc =
            NativeMappings.pcap_compile(
                handle,
                prog,
                bpfExpression,
                mode.getValue(),
                ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0));
      }
      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }

    return new BpfProgram(prog, bpfExpression);
  }

  /**
   * @param bpfExpression bpfExpression
   * @param mode mode
   * @param netmask netmask
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void setFilter(String bpfExpression, BpfCompileMode mode, Inet4Address netmask)
      throws PcapNativeException, NotOpenException {
    if (bpfExpression == null || mode == null || netmask == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("bpfExpression: ")
          .append(bpfExpression)
          .append(" mode: ")
          .append(mode)
          .append(" netmask: ")
          .append(netmask);
      throw new NullPointerException(sb.toString());
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      bpf_program prog = new bpf_program();
      try {
        int mask = ByteArrays.getInt(ByteArrays.toByteArray(netmask), 0);
        int rc;
        synchronized (compileLock) {
          rc = NativeMappings.pcap_compile(handle, prog, bpfExpression, mode.getValue(), mask);
        }
        if (rc < 0) {
          throw new PcapNativeException("Error occurred in pcap_compile: " + getError(), rc);
        }

        rc = NativeMappings.pcap_setfilter(handle, prog);
        if (rc < 0) {
          throw new PcapNativeException("Error occurred in pcap_setfilter: " + getError(), rc);
        }

        this.filteringExpression = bpfExpression;
      } finally {
        NativeMappings.pcap_freecode(prog);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @param bpfExpression bpfExpression
   * @param mode mode
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void setFilter(String bpfExpression, BpfCompileMode mode)
      throws PcapNativeException, NotOpenException {
    setFilter(bpfExpression, mode, PCAP_NETMASK_UNKNOWN);
  }

  /**
   * @param prog prog
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void setFilter(BpfProgram prog) throws PcapNativeException, NotOpenException {
    if (prog == null) {
      throw new NullPointerException("prog is null.");
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_setfilter(handle, prog.getProgram());
      if (rc < 0) {
        throw new PcapNativeException("Failed to set filter: " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }

    this.filteringExpression = prog.getExpression();
  }

  /**
   * @param mode mode
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void setBlockingMode(BlockingMode mode) throws PcapNativeException, NotOpenException {
    if (mode == null) {
      StringBuilder sb = new StringBuilder();
      sb.append(" mode: ").append(mode);
      throw new NullPointerException(sb.toString());
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      PcapErrbuf errbuf = new PcapErrbuf();
      int rc = NativeMappings.pcap_setnonblock(handle, mode.getValue(), errbuf);
      if (rc < 0) {
        throw new PcapNativeException(errbuf.toString(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @return blocking mode
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public BlockingMode getBlockingMode() throws PcapNativeException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    PcapErrbuf errbuf = new PcapErrbuf();
    int rc;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_getnonblock(handle, errbuf);
    } finally {
      handleLock.readLock().unlock();
    }

    if (rc == 0) {
      return BlockingMode.BLOCKING;
    } else if (rc > 0) {
      return BlockingMode.NONBLOCKING;
    } else {
      throw new PcapNativeException(errbuf.toString(), rc);
    }
  }

  /**
   * @return a Packet object created from a captured packet using the packet factory. May be null.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public Packet getNextPacket() throws NotOpenException {
    byte[] ba = getNextRawPacket();
    if (ba == null) {
      return null;
    }

    return PacketFactories.getFactory(Packet.class, DataLinkType.class)
        .newInstance(ba, 0, ba.length, dlt);
  }

  /**
   * @return a captured packet. May be null.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public byte[] getNextRawPacket() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    pcap_pkthdr header = new pcap_pkthdr();
    header.setAutoSynch(false);
    Pointer packet;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      packet = NativeMappings.pcap_next(handle, header);
    } finally {
      handleLock.readLock().unlock();
    }

    if (packet != null) {
      Pointer headerP = header.getPointer();
      timestamps.set(buildTimestamp(headerP));
      originalLengths.set(pcap_pkthdr.getLen(headerP));
      return packet.getByteArray(0, pcap_pkthdr.getCaplen(headerP));
    } else {
      return null;
    }
  }

  /**
   * @return a Packet object created from a captured packet using the packet factory. Not null.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws EOFException if packets are being read from a pcap file and there are no more packets
   *     to read from the file.
   * @throws TimeoutException if packets are being read from a live capture and the timeout expired.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public Packet getNextPacketEx()
      throws PcapNativeException, EOFException, TimeoutException, NotOpenException {
    byte[] ba = getNextRawPacketEx();
    return PacketFactories.getFactory(Packet.class, DataLinkType.class)
        .newInstance(ba, 0, ba.length, dlt);
  }

  /**
   * @return a captured packet. Not null.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws EOFException if packets are being read from a pcap file and there are no more packets
   *     to read from the file.
   * @throws TimeoutException if packets are being read from a live capture and the timeout expired.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public byte[] getNextRawPacketEx()
      throws PcapNativeException, EOFException, TimeoutException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      PointerByReference headerPP = new PointerByReference();
      PointerByReference dataPP = new PointerByReference();
      int rc = NativeMappings.pcap_next_ex(handle, headerPP, dataPP);
      switch (rc) {
        case 0:
          throw new TimeoutException();
        case 1:
          Pointer headerP = headerPP.getValue();
          Pointer dataP = dataPP.getValue();
          if (headerP == null || dataP == null) {
            throw new PcapNativeException(
                "Failed to get packet. *header: " + headerP + " *data: " + dataP);
          }

          timestamps.set(buildTimestamp(headerP));
          originalLengths.set(pcap_pkthdr.getLen(headerP));
          return dataP.getByteArray(0, pcap_pkthdr.getCaplen(headerP));
        case -1:
          throw new PcapNativeException("Error occurred in pcap_next_ex(): " + getError(), rc);
        case -2:
          throw new EOFException();
        default:
          throw new PcapNativeException("Unexpected error occurred: " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * A wrapper method for <code>int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</code>. This
   * method creates a Packet object from a captured packet using the packet factory and passes it to
   * <code>listener.gotPacket(Packet)</code>. When a packet is captured, <code>
   * listener.gotPacket(Packet)</code> is called in the thread which called the <code>loop()
   * </code>. And then this PcapHandle waits for the thread to return from the <code>gotPacket()
   * </code> before it retrieves the next packet from the pcap buffer.
   *
   * @param packetCount the number of packets to capture. -1 is equivalent to infinity. 0 may result
   *     in different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void loop(int packetCount, PacketListener listener)
      throws PcapNativeException, InterruptedException, NotOpenException {
    loop(packetCount, listener, SimpleExecutor.getInstance());
  }

  /**
   * A wrapper method for <code>int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</code>. This
   * method creates a Packet object from a captured packet using the packet factory and passes it to
   * <code>listener.gotPacket(Packet)</code>. When a packet is captured, the {@link
   * java.util.concurrent.Executor#execute(Runnable) executor.execute()} is called with a Runnable
   * object in the thread which called the <code>loop()</code>. Then, the Runnable object calls
   * <code>listener.gotPacket(Packet)</code>. If <code>listener.gotPacket(Packet)</code> is expected
   * to take a long time to process a packet, this method should be used with a proper executor
   * instead of {@link #loop(int, PacketListener)} in order to prevent the pcap buffer from
   * overflowing.
   *
   * @param packetCount the number of packets to capture. -1 is equivalent to infinity. 0 may result
   *     in different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @param executor executor
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void loop(int packetCount, PacketListener listener, Executor executor)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener).append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }
    doLoop(packetCount, new GotPacketFuncExecutor(listener, dlt, executor));
  }

  /**
   * A wrapper method for <code>int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</code>. When a
   * packet is captured, <code>listener.gotPacket(byte[])</code> is called in the thread which
   * called the <code>loop()</code>. And then this PcapHandle waits for the thread to return from
   * the <code>gotPacket()</code> before it retrieves the next packet from the pcap buffer.
   *
   * @param packetCount the number of packets to capture. -1 is equivalent to infinity. 0 may result
   *     in different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void loop(int packetCount, RawPacketListener listener)
      throws PcapNativeException, InterruptedException, NotOpenException {
    loop(packetCount, listener, SimpleExecutor.getInstance());
  }

  /**
   * A wrapper method for <code>int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</code>. When a
   * packet is captured, the {@link java.util.concurrent.Executor#execute(Runnable)
   * executor.execute()} is called with a Runnable object in the thread which called the <code>
   * loop()</code>. Then, the Runnable object calls <code>listener.gotPacket(byte[])</code>. If
   * <code>listener.gotPacket(byte[])</code> is expected to take a long time to process a packet,
   * this method should be used with a proper executor instead of {@link #loop(int,
   * RawPacketListener)} in order to prevent the pcap buffer from overflowing.
   *
   * @param packetCount the number of packets to capture. -1 is equivalent to infinity. 0 may result
   *     in different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @param executor executor
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void loop(int packetCount, RawPacketListener listener, Executor executor)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener).append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }
    doLoop(packetCount, new GotRawPacketFuncExecutor(listener, executor));
  }

  private void doLoop(int packetCount, NativeMappings.pcap_handler handler)
      throws PcapNativeException, InterruptedException, NotOpenException {

    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Starting loop.");
      int rc = NativeMappings.pcap_loop(handle, packetCount, handler, null);
      switch (rc) {
        case 0:
          logger.info("Finished loop.");
          break;
        case -1:
          throw new PcapNativeException("Error occurred: " + getError(), rc);
        case -2:
          logger.info("Broken.");
          throw new InterruptedException();
        default:
          throw new PcapNativeException("Unexpected error occurred: " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @param packetCount the maximum number of packets to process. If -1 is specified, all the
   *     packets in the pcap buffer or pcap file will be processed before returning. 0 may result in
   *     different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @return the number of captured packets.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int dispatch(int packetCount, PacketListener listener)
      throws PcapNativeException, InterruptedException, NotOpenException {
    return dispatch(packetCount, listener, SimpleExecutor.getInstance());
  }

  /**
   * @param packetCount the maximum number of packets to process. If -1 is specified, all the
   *     packets in the pcap buffer or pcap file will be processed before returning. 0 may result in
   *     different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @param executor executor
   * @return the number of captured packets.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int dispatch(int packetCount, PacketListener listener, Executor executor)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener).append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }
    return doDispatch(packetCount, new GotPacketFuncExecutor(listener, dlt, executor));
  }

  /**
   * @param packetCount the maximum number of packets to process. If -1 is specified, all the
   *     packets in the pcap buffer or pcap file will be processed before returning. 0 may result in
   *     different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @return the number of captured packets.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int dispatch(int packetCount, RawPacketListener listener)
      throws PcapNativeException, InterruptedException, NotOpenException {
    return dispatch(packetCount, listener, SimpleExecutor.getInstance());
  }

  /**
   * @param packetCount the maximum number of packets to process. If -1 is specified, all the
   *     packets in the pcap buffer or pcap file will be processed before returning. 0 may result in
   *     different behaviors between platforms and pcap library versions.
   * @param listener listener
   * @param executor executor
   * @return the number of captured packets.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public int dispatch(int packetCount, RawPacketListener listener, Executor executor)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (listener == null || executor == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("listener: ").append(listener).append(" executor: ").append(executor);
      throw new NullPointerException(sb.toString());
    }
    return doDispatch(packetCount, new GotRawPacketFuncExecutor(listener, executor));
  }

  private int doDispatch(int packetCount, NativeMappings.pcap_handler handler)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    int rc;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Starting dispatch.");
      rc = NativeMappings.pcap_dispatch(handle, packetCount, handler, null);
      if (rc < 0) {
        switch (rc) {
          case -1:
            throw new PcapNativeException("Error occurred: " + getError(), rc);
          case -2:
            logger.info("Broken.");
            throw new InterruptedException();
          default:
            throw new PcapNativeException("Unexpected error occurred: " + getError(), rc);
        }
      }
    } finally {
      handleLock.readLock().unlock();
    }

    logger.info("Finish dispatch.");
    return rc;
  }

  /**
   * @param filePath "-" means stdout. The dlt of the PcapHandle which captured the packets you want
   *     to dump must be the same as this dlt.
   * @return an opened PcapDumper.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public PcapDumper dumpOpen(String filePath) throws PcapNativeException, NotOpenException {
    if (filePath == null) {
      throw new NullPointerException("filePath must not be null.");
    }
    if (!open) {
      throw new NotOpenException();
    }

    Pointer dumper;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      dumper = NativeMappings.pcap_dump_open(handle, filePath);
      if (dumper == null) {
        throw new PcapNativeException(getError());
      }
    } finally {
      handleLock.readLock().unlock();
    }

    return new PcapDumper(dumper, timestampPrecision);
  }

  /**
   * @param packetCount packetCount
   * @param dumper dumper
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws InterruptedException if the loop terminated due to a call to {@link #breakLoop()}.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void loop(int packetCount, PcapDumper dumper)
      throws PcapNativeException, InterruptedException, NotOpenException {
    if (dumper == null) {
      throw new NullPointerException("dumper must not be null.");
    }
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Starting dump loop.");
      int rc =
          NativeMappings.pcap_loop(
              handle, packetCount, NativeMappings.PCAP_DUMP, dumper.getDumper());

      switch (rc) {
        case 0:
          logger.info("Finished dump loop.");
          break;
        case -1:
          throw new PcapNativeException("Error occurred: " + getError(), rc);
        case -2:
          logger.info("Broken.");
          throw new InterruptedException();
        default:
          throw new PcapNativeException("Unexpected error occurred: " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * Breaks a loop which this handle is working on.
   *
   * <p>The loop may not be broken immediately on some OSes because of buffering or something. As a
   * workaround, letting this capture some bogus packets after calling this method may work.
   *
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void breakLoop() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      logger.info("Break loop.");
      NativeMappings.pcap_breakloop(handle);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @param packet packet
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void sendPacket(Packet packet) throws PcapNativeException, NotOpenException {
    if (packet == null) {
      throw new NullPointerException("packet may not be null");
    }
    sendPacket(packet.getRawData());
  }

  /**
   * @param bytes raw bytes
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void sendPacket(byte[] bytes) throws NotOpenException, PcapNativeException {
    sendPacket(bytes, bytes.length);
  }

  /**
   * @param bytes raw bytes
   * @param len length
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   * @throws NullPointerException if any of arguments are null.
   */
  public void sendPacket(byte[] bytes, int len) throws NotOpenException, PcapNativeException {
    if (bytes == null) {
      throw new NullPointerException("bytes may not be null");
    }

    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      int rc = NativeMappings.pcap_sendpacket(handle, bytes, len);
      if (rc < 0) {
        throw new PcapNativeException("Error occurred in pcap_sendpacket(): " + getError(), rc);
      }
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /**
   * @return a {@link org.pcap4j.core.PcapStat PcapStat} object.
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public PcapStat getStats() throws PcapNativeException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      if (Platform.isWindows()) {
        IntByReference pcapStatSize = new IntByReference();
        Pointer psp = PcapLibrary.INSTANCE.win_pcap_stats_ex(handle, pcapStatSize);
        if (!getError()
            .equals("Cannot retrieve the extended statistics from a file or a TurboCap port")) {
          if (pcapStatSize.getValue() != 24) {
            throw new PcapNativeException(getError());
          }
          if (psp == null) {
            throw new PcapNativeException(getError());
          }
          return new PcapStat(psp, true);
        }
      }

      pcap_stat ps = new pcap_stat();
      ps.setAutoSynch(false);
      int rc = NativeMappings.pcap_stats(handle, ps);
      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }

      return new PcapStat(ps.getPointer(), false);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  //  /**
  //   *
  //   * @return a {@link org.pcap4j.core.PcapStatEx PcapStatEx} object.
  //   * @throws PcapNativeException if an error occurs in the pcap native library.
  //   * @throws NotOpenException if this PcapHandle is not open.
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
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public List<DataLinkType> listDatalinks() throws PcapNativeException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    List<DataLinkType> list;
    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }

      PointerByReference dltBufPP = new PointerByReference();
      int rc = NativeMappings.pcap_list_datalinks(handle, dltBufPP);
      if (rc < 0) {
        throw new PcapNativeException(getError(), rc);
      }

      Pointer dltBufP = dltBufPP.getValue();
      list = new ArrayList<DataLinkType>(rc);
      for (int i : dltBufP.getIntArray(0, rc)) {
        list.add(DataLinkType.getInstance(i));
      }
      NativeMappings.pcap_free_datalinks(dltBufP);
    } finally {
      handleLock.readLock().unlock();
    }

    return list;
  }

  /**
   * @return an error message.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public String getError() throws NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    if (!handleLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      return NativeMappings.pcap_geterr(handle).getString(0);
    } finally {
      handleLock.readLock().unlock();
    }
  }

  /** Closes this PcapHandle. */
  @Override
  public void close() {
    if (!open) {
      logger.warn("Already closed.");
      return;
    }

    handleLock.writeLock().lock();
    try {
      if (!open) {
        logger.warn("Already closed.");
        return;
      }
      open = false;
    } finally {
      handleLock.writeLock().unlock();
    }

    NativeMappings.pcap_close(handle);
    logger.info("Closed.");
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(60);

    sb.append("Link type: [")
        .append(dlt)
        .append("] handle: [")
        .append(handle)
        .append("] Open: [")
        .append(open)
        .append("] Filtering Expression: [")
        .append(filteringExpression)
        .append("]");

    return sb.toString();
  }

  private static final class SimpleExecutor implements Executor {

    private SimpleExecutor() {}

    private static final SimpleExecutor INSTANCE = new SimpleExecutor();

    public static SimpleExecutor getInstance() {
      return INSTANCE;
    }

    @Override
    public void execute(Runnable command) {
      command.run();
    }
  }

  private final class GotPacketFuncExecutor implements NativeMappings.pcap_handler {

    private final DataLinkType dlt;
    private final PacketListener listener;
    private final Executor executor;

    public GotPacketFuncExecutor(PacketListener listener, DataLinkType dlt, Executor executor) {
      this.dlt = dlt;
      this.listener = listener;
      this.executor = executor;
    }

    @Override
    public void got_packet(Pointer args, Pointer header, final Pointer packet) {
      final Timestamp ts = buildTimestamp(header);
      final int len = pcap_pkthdr.getLen(header);
      final byte[] ba = packet.getByteArray(0, pcap_pkthdr.getCaplen(header));

      try {
        executor.execute(
            new Runnable() {
              @Override
              public void run() {
                timestamps.set(ts);
                originalLengths.set(len);
                listener.gotPacket(
                    PacketFactories.getFactory(Packet.class, DataLinkType.class)
                        .newInstance(ba, 0, ba.length, dlt));
              }
            });
      } catch (Throwable e) {
        logger.error("The executor has thrown an exception.", e);
      }
    }
  }

  private final class GotRawPacketFuncExecutor implements NativeMappings.pcap_handler {

    private final RawPacketListener listener;
    private final Executor executor;

    public GotRawPacketFuncExecutor(RawPacketListener listener, Executor executor) {
      this.listener = listener;
      this.executor = executor;
    }

    @Override
    public void got_packet(Pointer args, Pointer header, final Pointer packet) {
      final Timestamp ts = buildTimestamp(header);
      final int len = pcap_pkthdr.getLen(header);
      final byte[] ba = packet.getByteArray(0, pcap_pkthdr.getCaplen(header));

      try {
        executor.execute(
            new Runnable() {
              @Override
              public void run() {
                timestamps.set(ts);
                originalLengths.set(len);
                listener.gotPacket(ba);
              }
            });
      } catch (Throwable e) {
        logger.error("The executor has thrown an exception.", e);
      }
    }
  }

  private Timestamp buildTimestamp(Pointer header) {
    Timestamp ts = new Timestamp(pcap_pkthdr.getTvSec(header).longValue() * 1000L);
    switch (timestampPrecision) {
      case MICRO:
        ts.setNanos(pcap_pkthdr.getTvUsec(header).intValue() * 1000);
        break;
      case NANO:
        ts.setNanos(pcap_pkthdr.getTvUsec(header).intValue());
        break;
      default:
        throw new AssertionError("Never get here.");
    }
    return ts;
  }

  /**
   * This class is used to open (i.e. create and activate) a live capture handle as {@link
   * PcapNetworkInterface#openLive(int, PromiscuousMode, int) PcapNetworkInterface#openLive} does
   * but with more parameters.
   *
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
    private TimestampPrecision timestampPrecision = null;
    private PcapDirection direction = null;
    private boolean immediateMode;
    private boolean isImmediateModeSet = false;

    /** @param deviceName A value {@link PcapNetworkInterface#getName()} returns. */
    public Builder(String deviceName) {
      if (deviceName == null || deviceName.length() == 0) {
        throw new IllegalArgumentException("deviceName: " + deviceName);
      }
      this.deviceName = deviceName;
    }

    /**
     * @param snaplen Snapshot length, which is the number of bytes captured for each packet. If
     *     this method isn't called, the platform's default snaplen will be applied at {@link
     *     #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder snaplen(int snaplen) {
      this.snaplen = snaplen;
      this.isSnaplenSet = true;
      return this;
    }

    /**
     * @param promiscuousMode Promiscuous mode. If this method isn't called, the platform's default
     *     mode will be used at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder promiscuousMode(PromiscuousMode promiscuousMode) {
      this.promiscuousMode = promiscuousMode;
      return this;
    }

    /**
     * @param rfmon Whether monitor mode should be set on a PcapHandle when it is built. If true,
     *     monitor mode will be set, otherwise it will not be set. Some platforms don't support
     *     setting monitor mode. Calling this method on such platforms may cause PcapNativeException
     *     at {@link #build()}. If this method isn't called, the platform's default mode will be
     *     applied at {@link #build()} (if supported).
     * @return this Builder object for method chaining.
     */
    public Builder rfmon(boolean rfmon) {
      this.rfmon = rfmon;
      this.isRfmonSet = true;
      return this;
    }

    /**
     * @param timeoutMillis Read timeout. Most OSs buffer packets. The OSs pass the packets to
     *     Pcap4j after the buffer gets full or the read timeout expires. Must be non-negative. May
     *     be ignored by some OSs. 0 means disable buffering on Solaris. 0 means infinite on the
     *     other OSs. 1 through 9 means infinite on Solaris. If this method isn't called, the
     *     platform's default timeout will be applied at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder timeoutMillis(int timeoutMillis) {
      this.timeoutMillis = timeoutMillis;
      this.isTimeoutMillisSet = true;
      return this;
    }

    /**
     * @param bufferSize The buffer size, which is in units of bytes. If this method isn't called,
     *     the platform's default buffer size will be applied at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder bufferSize(int bufferSize) {
      this.bufferSize = bufferSize;
      this.isBufferSizeSet = true;
      return this;
    }

    /**
     * @param timestampPrecision The timestamp precision. If this method isn't called, microsecond
     *     precision will be applied at {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder timestampPrecision(TimestampPrecision timestampPrecision) {
      this.timestampPrecision = timestampPrecision;
      return this;
    }

    /**
     * Set direction flag, which controls whether we accept only incoming packets, only outgoing
     * packets, or both. Note that, depending on the platform, some or all direction arguments might
     * not be supported.
     *
     * @param direction The direction of packets to capture. If this method isn't called, no packets
     *     will be filtered by their direction.
     * @return this Builder object for method chaining.
     */
    public Builder direction(PcapDirection direction) {
      this.direction = direction;
      return this;
    }

    /**
     * Set immediate mode, which allows programs to process packets as soon as they arrive.
     *
     * @param immediateMode Whether immediate mode should be set on a PcapHandle when it is built.
     *     If true, immediate mode will be set, otherwise it will not be set. Some platforms and
     *     library versions don't support setting immediate mode. Calling this method in such cases
     *     may cause PcapNativeException at {@link #build()}. If this method isn't called, immediate
     *     mode will not be set {@link #build()}.
     * @return this Builder object for method chaining.
     */
    public Builder immediateMode(boolean immediateMode) {
      this.immediateMode = immediateMode;
      this.isImmediateModeSet = true;
      return this;
    }

    /**
     * @return a new PcapHandle object representing a live capture handle.
     * @throws PcapNativeException if an error occurs in the pcap native library.
     */
    public PcapHandle build() throws PcapNativeException {
      return new PcapHandle(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 0.9.16
   */
  public static enum SwappedType {

    /** */
    NOT_SWAPPED(0),

    /** */
    SWAPPED(1),

    /** */
    MAYBE_SWAPPED(2);

    private final int value;

    private SwappedType(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 0.9.15
   */
  public static enum BlockingMode {

    /** */
    BLOCKING(0),

    /** */
    NONBLOCKING(1);

    private final int value;

    private BlockingMode(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.5.1
   */
  public static enum TimestampPrecision {

    /** use timestamps with microsecond precision, default */
    MICRO(0),

    /** use timestamps with nanosecond precision */
    NANO(1);

    private final int value;

    private TimestampPrecision(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }

  /**
   * Direction of packets.
   *
   * <pre>
   * typedef enum {
   *   PCAP_D_INOUT = 0,
   *   PCAP_D_IN,
   *   PCAP_D_OUT
   * } pcap_direction_t;
   * </pre>
   *
   * @author Kaito Yamada
   * @version pcap4j 1.6.4
   */
  public static enum PcapDirection {

    /** Both inbound and outbound. */
    INOUT(0),

    /** Inbound only. */
    IN(1),

    /** Outbound only, */
    OUT(2);

    private final int value;

    private PcapDirection(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
