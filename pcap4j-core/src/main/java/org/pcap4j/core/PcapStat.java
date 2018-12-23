/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Pointer;
import org.pcap4j.core.NativeMappings.pcap_stat;
import org.pcap4j.core.NativeMappings.win_pcap_stat;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class PcapStat {

  private final long numPacketsReceived;
  private final long numPacketsDropped;
  private final long numPacketsDroppedByIf;
  private final long numPacketsCaptured;

  PcapStat(pcap_stat stat) {
    if (stat instanceof win_pcap_stat) {
      win_pcap_stat win_stat = (win_pcap_stat) stat;
      this.numPacketsReceived = win_stat.ps_recv & 0xFFFFFFFFL;
      this.numPacketsDropped = win_stat.ps_drop & 0xFFFFFFFFL;
      this.numPacketsDroppedByIf = win_stat.ps_ifdrop & 0xFFFFFFFFL;
      this.numPacketsCaptured = win_stat.bs_capt & 0xFFFFFFFFL;
    } else {
      this.numPacketsReceived = stat.ps_recv & 0xFFFFFFFFL;
      this.numPacketsDropped = stat.ps_drop & 0xFFFFFFFFL;
      this.numPacketsDroppedByIf = stat.ps_ifdrop & 0xFFFFFFFFL;
      this.numPacketsCaptured = 0;
    }
  }

  PcapStat(Pointer p, boolean isWinPcapStat) {
    this.numPacketsReceived = pcap_stat.getPsRecv(p) & 0xFFFFFFFFL;
    this.numPacketsDropped = pcap_stat.getPsDrop(p) & 0xFFFFFFFFL;
    this.numPacketsDroppedByIf = pcap_stat.getPsIfdrop(p) & 0xFFFFFFFFL;

    if (isWinPcapStat) {
      this.numPacketsCaptured = win_pcap_stat.getBsCapt(p) & 0xFFFFFFFFL;
    } else {
      this.numPacketsCaptured = 0;
    }
  }

  /** @return ps_recv */
  public long getNumPacketsReceived() {
    return numPacketsReceived;
  }

  /** @return ps_drop */
  public long getNumPacketsDropped() {
    return numPacketsDropped;
  }

  /** @return ps_ifdrop */
  public long getNumPacketsDroppedByIf() {
    return numPacketsDroppedByIf;
  }

  /** @return bs_capt, which is valid only on Windows. */
  public long getNumPacketsCaptured() {
    return numPacketsCaptured;
  }
}
