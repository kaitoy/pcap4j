/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import java.io.Closeable;
import java.sql.Timestamp;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.core.NativeMappings.timeval;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.9
 */
public final class PcapDumper implements Closeable {

  private static final Logger logger = LoggerFactory.getLogger(PcapDumper.class);

  private final Pointer dumper;
  private final TimestampPrecision timestampPrecision;
  private final ReentrantReadWriteLock dumperLock = new ReentrantReadWriteLock(true);

  private volatile boolean open = true;

  PcapDumper(Pointer dumper, TimestampPrecision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    this.dumper = dumper;
  }

  Pointer getDumper() {
    return dumper;
  }

  /** @return true if this PcapDumper is open; false otherwise. */
  public boolean isOpen() {
    return open;
  }

  /**
   * @param packet packet
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void dump(Packet packet) throws NotOpenException {
    dump(packet, new Timestamp(System.currentTimeMillis()));
  }

  /**
   * @param packet packet
   * @param timestamp timestamp
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void dump(Packet packet, Timestamp timestamp) throws NotOpenException {
    if (packet == null || timestamp == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("packet: ").append(packet).append(" ts: ").append(timestamp);
      throw new NullPointerException(sb.toString());
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Dumping a packet: " + packet);
    }
    dumpRaw(packet.getRawData(), timestamp);
  }

  /**
   * @param packet packet
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void dumpRaw(byte[] packet) throws NotOpenException {
    dumpRaw(packet, new Timestamp(System.currentTimeMillis()));
  }

  /**
   * @param packet packet
   * @param timestamp timestamp
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void dumpRaw(byte[] packet, Timestamp timestamp) throws NotOpenException {
    if (packet == null || timestamp == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("packet: ").append(packet).append(" timestamp: ").append(timestamp);
      throw new NullPointerException(sb.toString());
    }

    if (!open) {
      throw new NotOpenException();
    }

    pcap_pkthdr header = new pcap_pkthdr();
    header.len = header.caplen = packet.length;
    header.ts = new timeval();
    header.ts.tv_sec = new NativeLong(timestamp.getTime() / 1000L);
    switch (timestampPrecision) {
      case MICRO:
        header.ts.tv_usec = new NativeLong(timestamp.getNanos() / 1000L);
        break;
      case NANO:
        header.ts.tv_usec = new NativeLong(timestamp.getNanos());
        break;
      default:
        throw new AssertionError("Never get here.");
    }

    if (!dumperLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      NativeMappings.pcap_dump(dumper, header, packet);
    } finally {
      dumperLock.readLock().unlock();
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Dumped a packet: " + ByteArrays.toHexString(packet, " "));
    }
  }

  /**
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public void flush() throws PcapNativeException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    int rc;
    if (!dumperLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      rc = NativeMappings.pcap_dump_flush(dumper);
    } finally {
      dumperLock.readLock().unlock();
    }

    if (rc < 0) {
      throw new PcapNativeException("Failed to flush.", rc);
    }
  }

  /**
   * @return the file position for a "savefile".
   * @throws PcapNativeException if an error occurs in the pcap native library.
   * @throws NotOpenException if this PcapHandle is not open.
   */
  public long ftell() throws PcapNativeException, NotOpenException {
    if (!open) {
      throw new NotOpenException();
    }

    NativeLong nposition;
    if (!dumperLock.readLock().tryLock()) {
      throw new NotOpenException();
    }
    try {
      if (!open) {
        throw new NotOpenException();
      }
      nposition = NativeMappings.pcap_dump_ftell(dumper);
    } finally {
      dumperLock.readLock().unlock();
    }

    long position = nposition.longValue();
    if (position < 0) {
      throw new PcapNativeException("Failed to get the file position.");
    }

    return position;
  }

  /** */
  @Override
  public void close() {
    if (!open) {
      logger.warn("Already closed.");
      return;
    }

    dumperLock.writeLock().lock();
    try {
      if (!open) {
        logger.warn("Already closed.");
        return;
      }
      open = false;
    } finally {
      dumperLock.writeLock().unlock();
    }

    NativeMappings.pcap_dump_close(dumper);
    logger.info("Closed.");
  }
}
