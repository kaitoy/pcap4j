/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.core.NativeMappings.timeval;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.9
 */
public final class PcapDumper {

  private static final Logger logger = LoggerFactory.getLogger(PcapDumper.class);

  private final Pointer dumper;
  private final ReentrantReadWriteLock dumperLock = new ReentrantReadWriteLock(true);

  private volatile boolean open = true;

  PcapDumper(Pointer dumper) { this.dumper = dumper; }

  Pointer getDumper() { return dumper; }

  /**
   *
   * @return true if this PcapDumper is open; false otherwise.
   */
  public boolean isOpen() { return open; }

  /**
   *
   * @param packet
   * @throws NotOpenException
   */
  public void dump(Packet packet) throws NotOpenException {
    long cur = System.currentTimeMillis();
    long timestampSec = cur / 1000L;
    int timestampMicros = (int)((cur - timestampSec * 1000L) * 1000);
    dump(packet, timestampSec, timestampMicros);
  }

  /**
   *
   * @param packet
   * @param timestampSec
   * @param timestampMicros
   * @throws NotOpenException
   */
  public void dump(
    Packet packet, long timestampSec, int timestampMicros
  ) throws NotOpenException {
    if (packet == null) {
      throw new NullPointerException("packet may not be null");
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Dumping a packet: " + packet);
    }
    dumpRaw(packet.getRawData(), timestampSec, timestampMicros);
  }

  /**
   *
   * @param packet
   * @throws NotOpenException
   */
  public void dumpRaw(byte[] packet) throws NotOpenException {
    long cur = System.currentTimeMillis();
    long timestampSec = cur / 1000L;
    int timestampMicros = (int)((cur - timestampSec * 1000L) * 1000);
    dumpRaw(packet, timestampSec, timestampMicros);
  }

  /**
   *
   * @param packet
   * @param timestampSec
   * @param timestampMicros
   * @throws NotOpenException
   */
  public void dumpRaw(
    byte[] packet, long timestampSec, int timestampMicros
  ) throws NotOpenException {
    if (timestampSec < 0) {
      throw new IllegalArgumentException(
              "timestampSec must be positive: "
                + timestampSec
            );
    }
    if (timestampMicros < 0 || timestampMicros >= 1000000) {
      throw new IllegalArgumentException(
              "timestampMicros must be between 0 and 999999: "
                + timestampMicros
            );
    }
    if (packet == null) {
      throw new NullPointerException("packet may not be null");
    }
    if (!open) {
      throw new NotOpenException();
    }

    pcap_pkthdr header = new pcap_pkthdr();
    header.len = header.caplen = packet.length;
    header.ts = new timeval();
    header.ts.tv_sec = new NativeLong(timestampSec);
    header.ts.tv_usec = new NativeLong(timestampMicros);

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
   * @throws PcapNativeException
   * @throws NotOpenException
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
   * @throws PcapNativeException
   * @throws NotOpenException
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

  /**
   *
   */
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
