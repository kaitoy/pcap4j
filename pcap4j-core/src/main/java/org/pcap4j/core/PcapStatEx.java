/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.math.BigInteger;
import org.pcap4j.core.NativeMappings.pcap_stat_ex;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.1
 */
public final class PcapStatEx {

  private final BigInteger rxNumPackets;
  private final BigInteger txNumPackets;
  private final BigInteger rxNumBytes;
  private final BigInteger txNumBytes;
  private final BigInteger rxNumPacketsError;
  private final BigInteger txNumPacketsError;
  private final BigInteger rxNumPacketsDropped;
  private final BigInteger txNumPacketsDropped;
  private final BigInteger rxNumMulticastPackets;
  private final BigInteger numCollisions;
  private final BigInteger rxNumLenghErrors;
  private final BigInteger txNumOverflowErrors;
  private final BigInteger rxNumCrcErrors;
  private final BigInteger rxNumFrameErrors;
  private final BigInteger rxNumFifoErrors;
  private final BigInteger rxNumMissedErrors;
  private final BigInteger txNumAbortedErrors;
  private final BigInteger txNumCarrierErrors;
  private final BigInteger txNumFifoErrors;
  private final BigInteger txNumHeartbeatErrors;
  private final BigInteger txNumWindowErrors;

  PcapStatEx(pcap_stat_ex stat) {
    this.rxNumPackets = new BigInteger(stat.rx_packets.toString());
    this.txNumPackets = new BigInteger(stat.tx_packets.toString());
    this.rxNumBytes = new BigInteger(stat.rx_bytes.toString());
    this.txNumBytes = new BigInteger(stat.tx_bytes.toString());
    this.rxNumPacketsError = new BigInteger(stat.rx_errors.toString());
    this.txNumPacketsError = new BigInteger(stat.tx_errors.toString());
    this.rxNumPacketsDropped = new BigInteger(stat.rx_dropped.toString());
    this.txNumPacketsDropped = new BigInteger(stat.tx_dropped.toString());
    this.rxNumMulticastPackets = new BigInteger(stat.multicast.toString());
    this.numCollisions = new BigInteger(stat.collisions.toString());
    this.rxNumLenghErrors = new BigInteger(stat.rx_length_errors.toString());
    this.txNumOverflowErrors = new BigInteger(stat.rx_over_errors.toString());
    this.rxNumCrcErrors = new BigInteger(stat.rx_crc_errors.toString());
    this.rxNumFrameErrors = new BigInteger(stat.rx_frame_errors.toString());
    this.rxNumFifoErrors = new BigInteger(stat.rx_fifo_errors.toString());
    this.rxNumMissedErrors = new BigInteger(stat.rx_missed_errors.toString());
    this.txNumAbortedErrors = new BigInteger(stat.tx_aborted_errors.toString());
    this.txNumCarrierErrors = new BigInteger(stat.tx_carrier_errors.toString());
    this.txNumFifoErrors = new BigInteger(stat.tx_fifo_errors.toString());
    this.txNumHeartbeatErrors = new BigInteger(stat.tx_heartbeat_errors.toString());
    this.txNumWindowErrors = new BigInteger(stat.tx_window_errors.toString());
  }

  /** @return the number of packets received. */
  public BigInteger getRxNumPackets() {
    return rxNumPackets;
  }

  /** @return the number of packets transmitted. */
  public BigInteger getTxNumPackets() {
    return txNumPackets;
  }

  /** @return the number of bytes received. */
  public BigInteger getRxNumBytes() {
    return rxNumBytes;
  }

  /** @return the number of bytes transmitted. */
  public BigInteger getTxNumBytes() {
    return txNumBytes;
  }

  /** @return the number of packets received with error. */
  public BigInteger getRxNumPacketsError() {
    return rxNumPacketsError;
  }

  /** @return the number of packets transmitted with error. */
  public BigInteger getTxNumPacketsError() {
    return txNumPacketsError;
  }

  /** @return the number of packets the receiver dropped. */
  public BigInteger getRxNumPacketsDropped() {
    return rxNumPacketsDropped;
  }

  /** @return the number of packets the transmitter dropped. */
  public BigInteger getTxNumPacketsDropped() {
    return txNumPacketsDropped;
  }

  /** @return the number of multicast packets received. */
  public BigInteger getRxNumMulticastPackets() {
    return rxNumMulticastPackets;
  }

  /** @return the number of collisions. */
  public BigInteger getNumCollisions() {
    return numCollisions;
  }

  /** @return the number of length errors in the receiver. */
  public BigInteger getRxNumLenghErrors() {
    return rxNumLenghErrors;
  }

  /** @return the number of buffer overflow errors in the transmitter. */
  public BigInteger getTxNumOverflowErrors() {
    return txNumOverflowErrors;
  }

  /** @return the number of CRC errors in the receiver. */
  public BigInteger getRxNumCrcErrors() {
    return rxNumCrcErrors;
  }

  /** @return the number of frame alignment errors in the receiver. */
  public BigInteger getRxNumFrameErrors() {
    return rxNumFrameErrors;
  }

  /** @return the number of fifo overrun errors in the receiver. */
  public BigInteger getRxNumFifoErrors() {
    return rxNumFifoErrors;
  }

  /** @return the number of packets the receiver missed. */
  public BigInteger getRxNumMissedErrors() {
    return rxNumMissedErrors;
  }

  /** @return the number of aborted errors in the transmitter. */
  public BigInteger getTxNumAbortedErrors() {
    return txNumAbortedErrors;
  }

  /** @return the number of times carrier sense signal lost during transmission. */
  public BigInteger getTxNumCarrierErrors() {
    return txNumCarrierErrors;
  }

  /** @return the number of fifo underrun errors in the transmitter. */
  public BigInteger getTxNumFifoErrors() {
    return txNumFifoErrors;
  }

  /** @return the number of heartbeat errors in the transmitter. */
  public BigInteger getTxNumHeartbeatErrors() {
    return txNumHeartbeatErrors;
  }

  /** @return the number of window errors in the transmitter. */
  public BigInteger getTxNumWindowErrors() {
    return txNumWindowErrors;
  }
}
