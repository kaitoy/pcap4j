/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.core.NativeMappings.pcap_pkthdr;
import org.pcap4j.core.NativeMappings.timeval;
import org.pcap4j.packet.Packet;
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
  private final Object thisLock = new Object();

  private volatile boolean opening = true;

  PcapDumper(Pointer dumper) { this.dumper = dumper; }

  Pointer getDumper() { return dumper; }

  /**
   *
   * @return
   */
  public boolean isOpening() { return opening; }

  /**
   *
   * @param packet
   */
  public void dump(Packet packet) {
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
   * @throws IllegalStateException
   */
  public void dump(Packet packet, long timestampSec, int timestampMicros) {
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

    pcap_pkthdr header = new pcap_pkthdr();
    header.len = header.caplen = packet.length();
    header.ts = new timeval();
    header.ts.tv_sec = new NativeLong(timestampSec);
    header.ts.tv_usec = new NativeLong(timestampMicros);

    synchronized (thisLock) {
      if (!opening) {
        throw new IllegalStateException("Not opening.");
      }
      //PcapLibrary.INSTANCE.pcap_dump(dumper, header, packet.getRawData());
      NativeMappings.pcap_dump(dumper, header, packet.getRawData());
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Dumped a packet: " + packet);
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
      // PcapLibrary.INSTANCE.pcap_dump_close(dumper);
      NativeMappings.pcap_dump_close(dumper);
      opening = false;
    }

    logger.info("Closed.");
  }

}
